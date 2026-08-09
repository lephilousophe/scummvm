package org.scummvm.scummvm.tts;

import android.media.AudioFormat;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.FloatBuffer;
import java.nio.ShortBuffer;
import java.util.ArrayList;
import java.util.Arrays;

public class PYinPitchTracker {
	private final ArrayList<ArrayList<PitchResult>> _pitches;

	private final float _sampleRate;
	private final float _minTau;

	private final int _inputFormat;
	private final int _inputChannelCount;
	private final int _inputFramesDivider;
	private final float _inputScale;

	private final float[] _buffer;
	private final float[] _diffBuffer;
	private final float[] _cmndBuffer;

	private int _bufferRd;
	private int _bufferWr;

	// pYIN specific thresholds
	//private static final float THRESHOLD_MIN = 0.01f;
	private static final float THRESHOLD_MAX = 0.3f; // Look for candidates up to this threshold
	// Tuning parameters: adjust these to change how aggressively the HMM smooths
	private static final float PITCH_JUMP_PENALTY = 5.0f;    // Penalizes large frequency jumps
	private static final float VOICING_DISABLE_PENALTY = 3.0f;// Penalizes switching between Voiced/Unvoiced
	private static final float VOICING_ENABLE_PENALTY = 1.0f;// Penalizes switching between Voiced/Unvoiced

	private static class PitchResult {
		public final float pitchHz;
		public final float probability; // 0.0 to 1.0

		public PitchResult(float pitchHz, float probability) {
			this.pitchHz = pitchHz;
			this.probability = probability;
		}
	}

	private static class PitchCandidate {
		int tau;
		float cmndValue;

		PitchCandidate(int tau, float cmndValue) {
			this.tau = tau;
			this.cmndValue = cmndValue;
		}
	}

	/**
	 * @param sampleRateInHz The audio sample rate (e.g., 44100)
	 * @param audioFormat The audio format of the samples to process
	 * @param channelCount The channel count of the samples to process
	 * @param minFreq The minimum frequency to detect
	 */
	public PYinPitchTracker(int sampleRateInHz, int audioFormat, int channelCount, float minFreq, float maxFreq) {
		_pitches = new ArrayList<>();

		_sampleRate = sampleRateInHz;
		_minTau = _sampleRate / maxFreq;

		_inputFormat = audioFormat;
		_inputChannelCount = channelCount;
		int framesDivider = channelCount;
		float scale;
		if (_inputFormat == AudioFormat.ENCODING_PCM_8BIT) {
			scale = 255.f;
		} else if (_inputFormat == AudioFormat.ENCODING_PCM_16BIT) {
			framesDivider *= 2;
			scale = 32768.f;
		} else if (_inputFormat == AudioFormat.ENCODING_PCM_FLOAT) {
			framesDivider *= 4;
			scale = 1.f;
		} else {
			framesDivider = 0;
			scale = 0.f;
		}
		if (_inputChannelCount >= 2) {
			scale = scale * 2.f;
		}
		_inputScale = scale;
		_inputFramesDivider = framesDivider;

		assert(framesDivider > 0);

		int bufferSize = (int)Math.ceil(sampleRateInHz / minFreq);
		// The YIN algorithm requires looking ahead, so we only search the first half of the _buffer
		int maxTau = bufferSize / 2;
		_buffer = new float[bufferSize * 2];
		_diffBuffer = new float[maxTau];
		_cmndBuffer = new float[maxTau];
	}

	public void process(byte[] audio) {
		int inOffset = 0;
		while (inOffset < audio.length) {
			final int writable;
			if (_bufferWr == _buffer.length) {
				_bufferWr = 0;
			}
			if (_bufferRd <= _bufferWr) {
				writable = _buffer.length - _bufferWr;
			} else {
				writable = _bufferRd - _bufferWr;
			}
			int processingFrames = Math.min(writable, (audio.length - inOffset) / _inputFramesDivider);

			if (_inputFormat == AudioFormat.ENCODING_PCM_8BIT) {
				if (_inputChannelCount < 2) {
					for (int i = 0; i < processingFrames; i++) {
						_buffer[_bufferWr++] = (audio[inOffset] & 0xff) / _inputScale;
						inOffset += _inputFramesDivider;
					}
				} else {
					for (int i = 0; i < processingFrames; i++) {
						_buffer[_bufferWr++] = ((audio[inOffset] & 0xff) + (audio[inOffset + 1] & 0xff)) / _inputScale;
						inOffset += _inputFramesDivider;
					}
				}
			} else if (_inputFormat == AudioFormat.ENCODING_PCM_16BIT) {
				ShortBuffer tmpBuffer = ByteBuffer.wrap(audio, inOffset, processingFrames * _inputFramesDivider).order(ByteOrder.LITTLE_ENDIAN).asShortBuffer();
				if (_inputChannelCount < 2) {
					for (int i = 0; i < processingFrames; i++) {
						_buffer[_bufferWr++] = tmpBuffer.get() / _inputScale;
					}
				} else if (_inputChannelCount == 2) {
					for (int i = 0; i < processingFrames; i++) {
						_buffer[_bufferWr++] = (tmpBuffer.get() + tmpBuffer.get()) / _inputScale;
					}
				} else {
					short[] buf = new short[_inputChannelCount];
					for (int i = 0; i < processingFrames; i++) {
						tmpBuffer.get(buf);
						_buffer[_bufferWr++] = (buf[0] + buf[1]) / _inputScale;
					}
				}
				inOffset += processingFrames * _inputFramesDivider;
			} else if (_inputFormat == AudioFormat.ENCODING_PCM_FLOAT) {
				FloatBuffer tmpBuffer = ByteBuffer.wrap(audio, inOffset, processingFrames * _inputFramesDivider).order(ByteOrder.LITTLE_ENDIAN).asFloatBuffer();
				if (_inputChannelCount < 2) {
					tmpBuffer.get(_buffer, _bufferWr, processingFrames);
					_bufferWr += processingFrames;
				} else if (_inputChannelCount == 2) {
					for (int i = 0; i < processingFrames; i++) {
						_buffer[_bufferWr++] = (tmpBuffer.get() + tmpBuffer.get()) / _inputScale;
					}
				} else {
					float[] buf = new float[_inputChannelCount];
					for (int i = 0; i < processingFrames; i++) {
						tmpBuffer.get(buf);
						_buffer[_bufferWr++] = (buf[0] + buf[1]) / _inputScale;
					}
				}
				inOffset += processingFrames * _inputFramesDivider;
			}

			int readable;
			if (_bufferRd >= _bufferWr) {
				readable = _buffer.length - _bufferRd + _bufferWr;
			} else {
				readable =  _bufferWr - _bufferRd;
			}

			final int tauMax = _diffBuffer.length;
			while (readable >= 2 * tauMax) {
				processFrame();

				// Hop by bufferSize / 4
				int hop = tauMax / 2;

				readable -= hop;
				_bufferRd += hop;
				if (_bufferRd >= _buffer.length) {
					_bufferRd -= _buffer.length;
				}
			}
		}
	}

	private void processFrame() {
		final int tauMax = _diffBuffer.length;

		int bufferEnd = _bufferRd + 2 * tauMax;
		if (bufferEnd >= _buffer.length) {
			bufferEnd -= _buffer.length;
		}

		// Step 1: Difference Function
		if (_bufferRd < bufferEnd) {
			// In this case, s1 and s2 never wrap
			for (int tau = 0; tau < tauMax; tau++) {
				_diffBuffer[tau] = 0;
				int s1 = _bufferRd;
				int s2 = _bufferRd + tau;
				for (int j = 0; j < tauMax; j++) {
					float delta = _buffer[s1] - _buffer[s2];
					_diffBuffer[tau] += delta * delta;
					s1++;
					s2++;
				}
			}
		} else {
			Arrays.fill(_diffBuffer,0);
			for (int j = 0; j < tauMax; j++) {
				int s1 = _bufferRd + j;
				if (s1 >= _buffer.length) {
					s1 -= _buffer.length;
				}
				for (int tau = 0; tau < tauMax; tau++) {
					int s2 = s1 + tau;
					if (s2 >= _buffer.length) {
						s2 -= _buffer.length;
					}
					float delta = _buffer[s1] - _buffer[s2];
					_diffBuffer[tau] += delta * delta;
				}
			}
		}

		// Step 2: Cumulative Mean Normalized Difference (CMND)
		_cmndBuffer[0] = 1.0f;
		float runningSum = 0;
		for (int tau = 1; tau < tauMax; tau++) {
			runningSum += _diffBuffer[tau];
			if (runningSum == 0) {
				_cmndBuffer[tau] = 1.0f;
			} else {
				_cmndBuffer[tau] = _diffBuffer[tau] * tau / runningSum;
			}
		}

		// Step 3: Probabilistic Candidate Extraction (The "p" in pYIN)
		ArrayList<PitchCandidate> candidates = new ArrayList<>();
		for (int tau = 2; tau < tauMax - 1; tau++) {
			// Find local minima
			if (_cmndBuffer[tau] < _cmndBuffer[tau - 1] && _cmndBuffer[tau] < _cmndBuffer[tau + 1]) {
				if (_cmndBuffer[tau] < THRESHOLD_MAX) {
					candidates.add(new PitchCandidate(tau, _cmndBuffer[tau]));
				}
			}
		}

		/*
		// This is simple YIN
		if (candidates.isEmpty()) {
			return new PitchResult(-1.0f, 0.0f); // Unvoiced / No pitch detected
		}

		// Step 4: Evaluate candidates
		// In real-time pYIN, without full HMM look-ahead, we calculate a probability
		// based on how deep the CMND dip is (confidence).
		PitchCandidate bestCandidate = null;
		float bestProbability = -1.0f;

		for (PitchCandidate candidate : candidates) {
			// Convert CMND dip depth to a probability metric (1.0 - CMND)
			float probability = 1.0f - candidate.cmndValue;

			// Bias towards lower tau (higher frequency) to avoid octave-down errors,
			// a common technique in probabilistic YIN implementations.
			float octaveBias = (float) candidate.tau / tauMax;
			float adjustedProbability = probability - (octaveBias * 0.1f);

			if (adjustedProbability > bestProbability) {
				bestProbability = adjustedProbability;
				bestCandidate = candidate;
			}
		}

		if (bestCandidate == null || bestProbability < 0.4f) {
			return new PitchResult(-1.0f, 0.0f); // Unvoiced
		}

		// Step 5: Parabolic Interpolation for subsample accuracy
		float refinedTau = parabolicInterpolation(bestCandidate.tau);
		float pitchHz = _sampleRate / refinedTau;

		return new PitchResult(pitchHz, Math.max(0.0f, Math.min(1.0f, bestProbability)));
		*/

		ArrayList<PitchResult> frameCandidates = new ArrayList<>();

		// Always add an Unvoiced candidate with a base probability (e.g., 0.2)
		// If all voiced candidates have lower probability than this, the HMM leans towards unvoiced.
		frameCandidates.add(new PitchResult(-1.0f, 0.1f));

		for (PitchCandidate candidate : candidates) {
			// Convert CMND dip depth to a probability metric (1.0 - CMND)
			float probability = 1.0f - candidate.cmndValue;

			// Bias towards lower tau (higher frequency) to avoid octave-down errors,
			// a common technique in probabilistic YIN implementations.
			float octaveBias = (float) candidate.tau / _cmndBuffer.length;
			float adjustedProbability = probability - (octaveBias * 0.1f);

			if (adjustedProbability > 0.05f && candidate.tau >= _minTau) { // Only keep plausible candidates
				float refinedTau = parabolicInterpolation(candidate.tau);
				float pitchHz = _sampleRate / refinedTau;
				frameCandidates.add(new PitchResult(pitchHz, adjustedProbability));
			}
		}

		_pitches.add(frameCandidates);
	}

	private float parabolicInterpolation(int tau) {
		if (tau <= 0 || tau >= _cmndBuffer.length - 1) {
			return tau;
		}
		float s0 = _cmndBuffer[tau - 1];
		float s1 = _cmndBuffer[tau];
		float s2 = _cmndBuffer[tau + 1];

		float bottom = s2 + s0 - 2 * s1;
		if (bottom == 0.0f) {
			return tau;
		}
		float delta = (s0 - s2) / (2 * bottom);
		return tau + delta;
	}

	/**
	 * Runs the Viterbi algorithm over the sequence of candidate frames.
	 *
	 * @return An array of smoothed pitch frequencies in Hz (with -1.0f for unvoiced).
	 */
	public float[] smooth() {
		int numFrames = _pitches.size();
		if (numFrames == 0) return new float[0];

		// Trellis arrays: store the cumulative cost and backpointers
		// We use arrays of arrays because the number of candidates varies per frame
		float[][] cost = new float[numFrames][];
		int[][] backpointer = new int[numFrames][];

		// Initialize the first frame
		ArrayList<PYinPitchTracker.PitchResult> firstFrame = _pitches.get(0);
		cost[0] = new float[firstFrame.size()];
		backpointer[0] = new int[firstFrame.size()];

		for (int i = 0; i < firstFrame.size(); i++) {
			// Observation cost: -log(probability). Add a small epsilon to avoid log(0)
			cost[0][i] = (float) -Math.log(firstFrame.get(i).probability + 1e-6);
			backpointer[0][i] = -1;
		}

		// Forward pass: dynamic programming
		for (int t = 1; t < numFrames; t++) {
			ArrayList<PYinPitchTracker.PitchResult> currentCandidates = _pitches.get(t);
			ArrayList<PYinPitchTracker.PitchResult> prevCandidates = _pitches.get(t - 1);

			cost[t] = new float[currentCandidates.size()];
			backpointer[t] = new int[currentCandidates.size()];

			for (int currIdx = 0; currIdx < currentCandidates.size(); currIdx++) {
				PYinPitchTracker.PitchResult current = currentCandidates.get(currIdx);
				float obsCost = (float) -Math.log(current.probability + 1e-6);

				float minCost = Float.MAX_VALUE;
				int bestPrevIdx = -1;

				for (int prevIdx = 0; prevIdx < prevCandidates.size(); prevIdx++) {
					PYinPitchTracker.PitchResult prev = prevCandidates.get(prevIdx);

					float transitionCost = calculateTransitionCost(prev.pitchHz, current.pitchHz);
					float pathCost = cost[t - 1][prevIdx] + transitionCost + obsCost;

					if (pathCost < minCost) {
						minCost = pathCost;
						bestPrevIdx = prevIdx;
					}
				}

				cost[t][currIdx] = minCost;
				backpointer[t][currIdx] = bestPrevIdx;
			}
		}

		// Traceback: find the best ending state, then walk backward
		float[] smoothedPitch = new float[numFrames];

		float minFinalCost = Float.MAX_VALUE;
		int bestLastIdx = 0;
		for (int i = 0; i < cost[numFrames - 1].length; i++) {
			if (cost[numFrames - 1][i] < minFinalCost) {
				minFinalCost = cost[numFrames - 1][i];
				bestLastIdx = i;
			}
		}

		// Follow backpointers to reconstruct the path
		int currentIdx = bestLastIdx;
		for (int t = numFrames - 1; t >= 0; t--) {
			smoothedPitch[t] = _pitches.get(t).get(currentIdx).pitchHz;
			currentIdx = backpointer[t][currentIdx];
		}

		return smoothedPitch;
	}

	private static float calculateTransitionCost(float prevHz, float currHz) {
		boolean prevUnvoiced = (prevHz < 0);
		boolean currUnvoiced = (currHz < 0);

		if (prevUnvoiced && currUnvoiced) {
			return 0.0f; // Remaining unvoiced is cheap
		}
		if (prevUnvoiced != currUnvoiced) {
			return currUnvoiced ? VOICING_DISABLE_PENALTY : VOICING_ENABLE_PENALTY; // Switching states costs a penalty
		}

		// Both voiced: penalize based on frequency distance (cents/octaves)
		// Math.abs(log2(f1/f2)) measures proportional pitch distance.
		float pitchDistance = (float) Math.abs(Math.log(currHz / prevHz) / Math.log(2));
		return pitchDistance * PITCH_JUMP_PENALTY;
	}
}
