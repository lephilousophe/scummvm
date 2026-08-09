package org.scummvm.scummvm;

import android.content.Context;
import android.os.Bundle;
import android.speech.tts.TextToSpeech;
import android.speech.tts.UtteranceProgressListener;
import android.speech.tts.Voice;
import android.util.Log;

import androidx.annotation.Keep;
import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import org.scummvm.scummvm.tts.TextToSpeechClassifier;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public class TextToSpeechManager extends UtteranceProgressListener implements TextToSpeech.OnInitListener {
	protected native void updateVoices(String[] names);

	protected static class Utterance {
		Utterance(@NonNull String utteranceId) {
			id = utteranceId;
		}

		final String id;
		String text;
		float speechRate;
		float pitch;
		float volume;
		int activeVoice;

		boolean match(String text) {
			return CharSequence.compare(this.text, text) == 0;
		}
	}

	// These values are synchronized with backends/text-to-speech/android/android-text-to-speech.h
	protected final int STATE_BROKEN = 0;
	protected final int STATE_READY = 1;
	protected final int STATE_SPEAKING = 2;
	protected final int STATE_PAUSED = 3;

	// These values are synchronized with common/text-to-speech.h
	public final int ACTION_INTERRUPT = 0;
	public final int ACTION_INTERRUPT_NO_REPEAT = 1;
	/** @noinspection unused */
	public final int ACTION_QUEUE = 2;
	public final int ACTION_QUEUE_NO_REPEAT = 3;
	public final int ACTION_DROP = 4;

	private final String _obsoleteVoiceName;

	protected Context _context;
	protected TextToSpeech _tts;
	protected Locale _locale;
	protected final AtomicInteger _state = new AtomicInteger(STATE_BROKEN);
	protected final LinkedList<Utterance> _queue = new LinkedList<>();
	protected final AtomicReference<Utterance> _currentUtterance = new AtomicReference<>();
	private final AtomicInteger _utteranceCounter = new AtomicInteger();

	public static TextToSpeechManager make(Context context) {
		if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.LOLLIPOP) {
			return new TextToSpeechManager.Lollipop(context);
		} else {
			return new TextToSpeechManager(context);
		}
	}

	/*
	 * We need a specific class because having
	 * a member variable of an unknown type causes errors
	 */
	@RequiresApi(api = android.os.Build.VERSION_CODES.LOLLIPOP)
	private static class Lollipop extends TextToSpeechManager {
		protected Voice[] _voices = null;
		TextToSpeechClassifier _classifier = null;

		public Lollipop(Context context) {
			super(context);
		}

		@Override
		protected void speak(Utterance utterance) {
			if (0 <= utterance.activeVoice && utterance.activeVoice < _voices.length) {
				_tts.setVoice(_voices[utterance.activeVoice]);
			}
			Bundle bundle = new Bundle();
			bundle.putFloat(TextToSpeech.Engine.KEY_PARAM_VOLUME, utterance.volume);

			_tts.speak(utterance.text, TextToSpeech.QUEUE_ADD, bundle, utterance.id);
		}

		@Override
		protected void updateVoices() {
			// Very limited voices support afterward: no gender, no age
			// Every voice are listed independent of the chosen language, so filter them
			Locale currentLocale = _tts.getVoice().getLocale();
			Set<Voice> set =  _tts.getVoices();
			Iterator<Voice> it = set.iterator();
			while(it.hasNext()) {
				Voice v = it.next();
				if (!v.getLocale().equals(currentLocale)) {
					it.remove();
				}
			}
			_voices = set.toArray(new Voice[]{});
			Arrays.sort(_voices, (Voice l, Voice r) -> {
				boolean l_bool = l.isNetworkConnectionRequired();
				boolean r_bool = r.isNetworkConnectionRequired();
				if (l_bool != r_bool) {
					return l_bool ? 1 : -1;
				}
				int delta = l.getLatency() - r.getLatency();
				if (delta != 0) {
					return delta;
				}
				delta = l.getQuality() - r.getQuality();
				if (delta != 0) {
					return delta;
				}
				l_bool = l.getFeatures().contains("legacySetLanguageVoice");
				r_bool = r.getFeatures().contains("legacySetLanguageVoice");
				if (l_bool != r_bool) {
					return l_bool ? 1 : -1;
				}
				return l.getName().compareTo(r.getName());
			});

			// First notify native side with unknown gender
			{
				String[] voicesNames = new String[_voices.length];
				for (int i = 0; i < _voices.length; i++) {
					voicesNames[i] = '9' + _voices[i].getName();
				}
				updateVoices(voicesNames);
			}

			if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.M) {
				// Before Marshmallow we can't get the synthesis data
				// Hence we cannot guess the gender
				return;
			}

			// Don't update voices with old results
			if (_classifier != null) {
				_classifier.setListener(null);
			}

			long start = System.nanoTime();
			_classifier = TextToSpeechClassifier.make(_context, _voices, (voices, genders) -> {
				long end = System.nanoTime();
				Log.d(ScummVM.LOG_TAG, "TTS: MEASURE " + (end - start));
				String[] voicesNames = new String[voices.length];
				for (int i = 0; i < voices.length; i++) {
					voicesNames[i] = genders[i] + voices[i].getName();
				}
				updateVoices(voicesNames);
			});
		}
	}

	private TextToSpeechManager(Context context) {
		_context = context;
		_obsoleteVoiceName = context.getResources().getString(R.string.tts_voice_name);
		_locale = null;
		_tts = new TextToSpeech(context, this);
	}

	// Called by native side
	/** @noinspection unused */ @Keep
	public void shutdown() {
		_state.set(STATE_BROKEN);

		if (_tts == null) {
			return;
		}

		_tts.shutdown();
		synchronized (_queue) {
			_queue.clear();
		}
	}

	// Called by native side
	/** @noinspection unused */ @Keep
	public int getState() {
		return _state.get();
	}

	// Called by native side
	/** @noinspection unused */ @Keep
	public void setLanguage(String language) {
		String country = null;
		//language = "fr";
		//language = "ar";
		//language = "en"; country = "in";
		//language = "pt"; country = "pt";
		_locale = CompatHelpers.LocaleCompat.buildLocale(language, country);
		if (_state.get() == STATE_BROKEN) {
			return;
		}
		_tts.setLanguage(_locale);
		updateVoices();
	}

	// Called by native side
	/** @noinspection unused */ @Keep
	public boolean stop() {
		if (_state.get() == STATE_BROKEN) {
			return false;
		}

		synchronized (_queue) {
			_queue.clear();
			_state.set(STATE_READY);
		}
		_tts.stop();

		return true;
	}

	// Called by native side
	/** @noinspection unused */ @Keep
	public boolean pause() {
		if (_state.get() == STATE_BROKEN) {
			return false;
		}
		if (_state.get() == STATE_PAUSED) {
			return true;
		}
		if (_state.compareAndSet(STATE_SPEAKING, STATE_PAUSED)) {
			_tts.stop();
			return true;
		}
		return _state.compareAndSet(STATE_READY, STATE_PAUSED);
	}

	// Called by native side
	/** @noinspection unused */ @Keep
	public boolean resume() {
		if (_state.get() == STATE_BROKEN) {
			return false;
		}
		if (!_state.compareAndSet(STATE_PAUSED, STATE_READY)) {
			return false;
		}
		startNextSpeech(true);
		return true;
	}

	// Called by native side
	/** @noinspection unused */ @Keep
	public boolean say(String text, int action, int speechRate, int pitch, int volume, int activeVoice) {
		if (_state.get() == STATE_BROKEN) {
			return false;
		}

		Log.d(ScummVM.LOG_TAG, "TTS: will say " + " text: " + text + " action: " + action);
		synchronized (_queue) {
			Utterance currentUtterance = _currentUtterance.get();
			if (currentUtterance != null || !_queue.isEmpty()) {
				Log.d(ScummVM.LOG_TAG, "TTS: QUEUE NOT EMPTY APPLYING ACTION: " + action);
				if (action == ACTION_DROP) {
					Log.d(ScummVM.LOG_TAG, "TTS: DROP");
					return true;
				}
				if (action == ACTION_INTERRUPT) {
					Log.d(ScummVM.LOG_TAG, "TTS: STOPPING AND PUSHING");
					_queue.clear();
					_tts.stop();
				} else if (action == ACTION_INTERRUPT_NO_REPEAT) {
					_queue.clear();
					if (currentUtterance != null && currentUtterance.match(text)) {
						Log.d(ScummVM.LOG_TAG, "TTS: STOPPING AND THAT'S IT");
						// Current text matches: stop after it
						return true;
					} else {
						Log.d(ScummVM.LOG_TAG, "TTS: STOPPING AND PUSHING NO REPEAT");
						_tts.stop();
					}
				} else if (action == ACTION_QUEUE_NO_REPEAT) {
					Utterance bottom = _queue.pollLast();
					if (bottom == null) {
						bottom = currentUtterance;
					}
					if (bottom != null && bottom.match(text)) {
						Log.d(ScummVM.LOG_TAG, "TTS: NO REPEAT");
						return true;
					}
				}
			}

			Utterance utterance = new Utterance(nextUtteranceId());
			utterance.text = text;
			utterance.speechRate = speechRate / 100.f + 1.f;
			utterance.pitch = pitch / 200.f + 1.f;
			utterance.volume = volume / 100.f;
			utterance.activeVoice = activeVoice;
			_queue.add(utterance);
			Log.d(ScummVM.LOG_TAG, "TTS: pushing " + utterance.id + " text: " + utterance.text);
		}

		if (_state.get() == STATE_READY) {
			startNextSpeech(true);
		}

		return true;
	}

	private void startNextSpeech(boolean restart) {
		if (restart) {
			if (!_state.compareAndSet(STATE_READY, STATE_SPEAKING)) {
				return;
			}
		} else if (_state.get() != STATE_SPEAKING) {
			return;
		}

		Utterance utterance;
		synchronized (_queue) {
			Log.d(ScummVM.LOG_TAG, "TTS: SNS QUEUE SIZE " + _queue.size());
			utterance = _queue.pollFirst();
		}
		if (utterance == null) {
			// queue is empty
			_state.compareAndSet(STATE_SPEAKING, STATE_READY);
			return;
		}

		boolean set = _currentUtterance.compareAndSet(null, utterance);
		if (!set) {
			// we may have just asked for stop but we are still speaking
			// We will get called again eventually by onDone
			return;
		}

		_tts.setSpeechRate(utterance.speechRate);
		Log.d(ScummVM.LOG_TAG, "TTS: Use pitch " + utterance.pitch);
		_tts.setPitch(utterance.pitch);

		speak(utterance);
	}

	@SuppressWarnings({"deprecation", "RedundantSuppression"})
	protected void speak(Utterance utterance) {
		HashMap<String, String> params = new HashMap<>();
		params.put(TextToSpeech.Engine.KEY_PARAM_UTTERANCE_ID, utterance.id);
		params.put(TextToSpeech.Engine.KEY_PARAM_VOLUME, Float.toString(utterance.volume));
		_tts.speak(utterance.text, TextToSpeech.QUEUE_ADD, params);
	}

	protected String nextUtteranceId() {
		int newUtterance = _utteranceCounter.getAndIncrement();
		return Integer.toHexString(newUtterance);
	}

	protected void updateVoices() {
		// No voice support before Lollipop
		String[] voices = new String[] { _obsoleteVoiceName };
		updateVoices(voices);
	}

	// OnInitListener API
	@Override
	public void onInit(int status) {
		if (status != TextToSpeech.SUCCESS) {
			_tts = null;
			return;
		}

		_tts.setOnUtteranceProgressListener(this);
		if (_locale != null) {
			_tts.setLanguage(_locale);
			updateVoices();
		}
		_state.set(STATE_READY);
	}

	// UtteranceProgressListener API
	@Override
	public void onStart(String utteranceId) {
		Log.d(ScummVM.LOG_TAG, "TTS: onStart " + utteranceId);
		Log.d(ScummVM.LOG_TAG, "TTS: QUEUE SIZE " + _queue.size() + " CURRENT " + _currentUtterance.get());
		// Nothing to do
		Utterance utterance = _currentUtterance.get();
		assert(utterance != null && utterance.id.equals(utteranceId));
	}

	@Override
	public void onDone(String utteranceId) {
		Log.d(ScummVM.LOG_TAG, "TTS: onDone " + utteranceId);
		Log.d(ScummVM.LOG_TAG, "TTS: QUEUE SIZE " + _queue.size());
		Utterance utterance = _currentUtterance.get();
		assert(utterance.id.equals(utteranceId));
		boolean reset = _currentUtterance.compareAndSet(utterance, null);
		assert(reset);
		startNextSpeech(false);
	}

	@SuppressWarnings({"deprecation", "RedundantSuppression"})
	@Override
	public void onError(String utteranceId) {
		Log.d(ScummVM.LOG_TAG, "TTS: onError " + utteranceId);
		onDone(utteranceId);
	}

	@RequiresApi(api = android.os.Build.VERSION_CODES.M)
	@Override
	public void onStop(String utteranceId, boolean interrupted) {
		Log.d(ScummVM.LOG_TAG, "TTS: onStop " + utteranceId + " " + interrupted);
		// On Android M and above, onStop is called instead of onDone if it has been stopped
		onDone(utteranceId);
	}
}
