package org.scummvm.scummvm.tts;

import android.content.Context;
import android.os.Bundle;
import android.speech.tts.TextToSpeech;
import android.speech.tts.UtteranceProgressListener;
import android.speech.tts.Voice;

import androidx.annotation.RequiresApi;

import java.io.File;
import java.util.Arrays;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicReference;

@RequiresApi(api = android.os.Build.VERSION_CODES.M)
public class TextToSpeechClassifier extends UtteranceProgressListener implements TextToSpeech.OnInitListener, Runnable {
	public interface OnClassifiedListener {
		void onClassified(Voice[] voices, int[] genders);
	}

	public static final int GENDER_UNDETERMINED = -1;
	public static final int GENDER_MALE = 0;
	public static final int GENDER_FEMALE = 1;
	public static final int GENDER_UNKNOWN = 8;
	public static final int GENDER_UNKNOWN_NET = 9;

	private static final HashMap<String, Integer> _cache = new HashMap<>();

	private final AtomicReference<OnClassifiedListener> _listener;
	private final Thread _worker;

	private final TextToSpeech _tts;
	private final Voice[] _voices;
	private final int[] _genders;

	private final Object _synchronizer = new Object();
	private boolean _lastValid = false;
	private final File _sink;

	private PYinPitchTracker _tracker;
	private final KMeansPitchFeatures _kMeans;

	public static TextToSpeechClassifier make(Context context, Voice[] voices, OnClassifiedListener listener) {
		int[] genders = new int[voices.length];
		Arrays.fill(genders, GENDER_UNDETERMINED);

		// Setup easy genders
		int i = 0;
		boolean determined = true;
		for (Voice voice : voices) {
			if (voice.isNetworkConnectionRequired()) {
				genders[i] = GENDER_UNKNOWN_NET;
			} else {
				Integer gender = _cache.get(voice.getName());
				if (gender != null) {
					genders[i] = gender;
				} else {
					determined = false;
				}
			}
			i++;
		}

		if (determined) {
			listener.onClassified(voices, genders);
			return null;
		}

		// If we are not fully determined, do it again from scratch to avoid bad decisions
		for (i = 0; i < genders.length; i++) {
			if (genders[i] != GENDER_UNKNOWN_NET) {
				genders[i] = GENDER_UNDETERMINED;
			}
		}

		return new TextToSpeechClassifier(context, voices, genders, listener);
	}

	private TextToSpeechClassifier(Context context, Voice[] voices, int[] genders, OnClassifiedListener listener) {
		_voices = voices;
		_genders = genders;
		_listener = new AtomicReference<>(listener);

		_tts = new TextToSpeech(context, this);
		_sink = new File("/dev/null");
		_kMeans = new KMeansPitchFeatures();
		_worker = new Thread(this);
	}

	public void setListener(OnClassifiedListener listener) {
		_listener.set(listener);
	}

	@Override
	public void onInit(int status) {
		if (status != TextToSpeech.SUCCESS) {
			OnClassifiedListener listener = _listener.get();
			if (listener != null) {
				listener.onClassified(_voices, null);
			}
			return;
		}
		_tts.setOnUtteranceProgressListener(this);
		_worker.start();
	}

	public void run() {
		_tts.setPitch(1.f);
		_tts.setSpeechRate(1.f);

		int i = 0;
		for (Voice voice : _voices) {
			if (_genders[i] != GENDER_UNDETERMINED) {
				continue;
			}

			if (_listener.get() == null) {
				// Our caller seems to have gone elsewhere
				return;
			}

			_tts.setVoice(voice);

			synchronized (_synchronizer) {
				File tmp = new File("/data/user/0/org.scummvm.scummvm.debug/cache");
				tmp = new File(tmp, voice.getName() + ".dump");
				_tts.synthesizeToFile("e", Bundle.EMPTY, tmp, voice.getName());
				//_tts.speak("a", TextToSpeech.QUEUE_ADD, Bundle.EMPTY, voice.getName());
				try {
					_synchronizer.wait();
				} catch (InterruptedException e) {
					_tts.stop();
					OnClassifiedListener listener = _listener.get();
					if (listener != null) {
						listener.onClassified(_voices, null);
					}
					return;
				}

				if (!_lastValid) {
					// This happens if pYIN failed to find the pitch
					_genders[i] = GENDER_UNKNOWN;
					_cache.put(voice.getName(), GENDER_UNKNOWN);
				}
			}

			i++;
		}

		if (_listener.get() == null) {
			// Our caller seems to have gone elsewhere
			return;
		}

		KMeansPitchFeatures.KMeansResult result = _kMeans.fit(2, 20);
		float delta = Math.abs(result.centroids[0].medianCent - result.centroids[1].medianCent);
		if (delta < 300.f ||  // 20% ratio in cents
			result.centroids.length > result.assignments.length) { // Only one voice
			// Results are too close, there is an only cluster:
			// try to determine the gender using absolute values
			int gender;
			float mean;

			if (result.centroids.length > result.assignments.length) {
				mean = result.centroids[0].medianCent;
			} else {
				mean = (result.centroids[0].medianCent + result.centroids[1].medianCent) / 2;
			}

			if (mean < 8616) { // 145 Hz in cents
				gender = GENDER_MALE;
			} else if (mean > 8839) { // 165 Hz in cents
				gender = GENDER_FEMALE;
			} else {
				gender = GENDER_UNKNOWN;
			}
			for (i = 0; i < _genders.length; i++) {
				if (_genders[i] == GENDER_UNDETERMINED) {
					_genders[i] = gender;
					_cache.put(_voices[i].getName(), GENDER_UNKNOWN);
				}
			}
			OnClassifiedListener listener = _listener.get();
			if (listener != null) {
				listener.onClassified(_voices, _genders);
			}
			return;
		}

		int correction;
		if (result.centroids[0].medianCent < result.centroids[1].medianCent) {
			// 0 is male: no correction
			correction = GENDER_MALE;
		} else {
			// 0 is female: flip the result
			correction = GENDER_FEMALE;
		}
		i = 0;
		for (int assignment : result.assignments) {
			// Skip network voices
			while (_genders[i] != GENDER_UNDETERMINED) {
				i++;
			}
			assignment ^= correction;
			_genders[i] = assignment;
			_cache.put(_voices[i].getName(), assignment);
			i++;
		}

		OnClassifiedListener listener = _listener.get();
		if (listener != null) {
			listener.onClassified(_voices, _genders);
		}
	}

	@Override
	public void onDone(String utteranceId) {
		float[] pitches = _tracker.smooth();
		boolean lastValid = _kMeans.addSeries(pitches);
		_tracker = null;
		synchronized(_synchronizer) {
			_lastValid = lastValid;
			_synchronizer.notify();
		}
	}

	@SuppressWarnings({"deprecation", "RedundantSuppression"})
	@Override
	public void onError(String utteranceId) {

	}

	@Override
	public void onStart(String utteranceId) {

	}

	@Override
	public void onBeginSynthesis(String utteranceId, int sampleRateInHz, int audioFormat, int channelCount) {
		// We look for pitch between 50 and 400Hz
		_tracker = new PYinPitchTracker(sampleRateInHz, audioFormat, channelCount, 50, 400);
	}

	@Override
	public void onAudioAvailable(String utteranceId, byte[] audio) {
		_tracker.process(audio);
	}
}
