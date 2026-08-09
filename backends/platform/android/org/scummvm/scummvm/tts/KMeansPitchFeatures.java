package org.scummvm.scummvm.tts;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

public class KMeansPitchFeatures {
	public static class KMeansResult {
		public final PitchFeatures[] centroids;
		public final int[] assignments;

		public KMeansResult(PitchFeatures[] centroids, int[] assignments) {
			this.centroids = centroids;
			this.assignments = assignments;
		}
	}

	public static class PitchFeatures {
		public final float medianCent;
		public final float amplitudeFactor;

		public PitchFeatures(float[] pitches) {
			Arrays.sort(pitches);

			if (pitches.length == 0 || pitches[pitches.length - 1] < 0) {
				// Empty pitches or made only of unvoiced data
				this.medianCent = Float.NaN;
				this.amplitudeFactor = Float.NaN;

				return;
			}

			// We have at least the last value being valid
			int start = pitches.length - 1;

			// Now perform a binary search
			int left = 0;
			int right = start - 1;
			while(left <= right) {
				// assume left + right will not overflow
				final int mid = (left + right) / 2;
				if (pitches[mid] < 0) {
					// Everything before mid is invalid
					left = mid + 1;
				} else {
					start = mid;
					right = mid - 1;
				}
			}

			int len = pitches.length - start;

			// Use nearest-rank quartile
			float p25 = pitches[start + ((len + 3) / 4)];
			float p75 = pitches[start + ((3*len + 3) / 4)];
			medianCent = 1200.f * (float)(Math.log(pitches[start + (len + 1) / 2]) / Math.log(2.0));
			// Try to get a value comparable in amplitude to medianCent as required by k-Means
			// Using the interquartile ratio here makes it like doing a delta in log domain
			amplitudeFactor = this.medianCent * (p75 / p25);
		}

		public PitchFeatures(PitchFeatures o) {
			medianCent = o.medianCent;
			amplitudeFactor = o.amplitudeFactor;
		}

		// Computes the barycenter of all points pertaining to the specified cluster
		public PitchFeatures(ArrayList<PitchFeatures> points, int[] assignments, int cluster) {
			float sumMeanHz = 0;
			float sumAmpHz = 0;
			int numPoints = 0;

			int i;
			for (i = 0; i < assignments.length; i++) {
				if (assignments[i] != cluster) {
					continue;
				}
				PitchFeatures point = points.get(i);
				sumMeanHz += point.medianCent;
				sumAmpHz += point.amplitudeFactor;
				numPoints++;
			}
			if (numPoints > 0) {
				medianCent = sumMeanHz / numPoints;
				amplitudeFactor = sumAmpHz / numPoints;
			} else {
				medianCent = Float.NEGATIVE_INFINITY;
				amplitudeFactor = Float.NEGATIVE_INFINITY;
			}
		}

		public boolean invalid() {
			return Float.isNaN(medianCent);
		}

		public float distanceSquared(PitchFeatures o) {
			// Make min and max weigh more
			float dMedian = medianCent - o.medianCent;
			float dAmp = amplitudeFactor - o.amplitudeFactor;
			return dMedian * dMedian + dAmp * dAmp;
		}
	}

	/*
	public static class PitchFeatures {
		public final float medianCent;
		public final float fig1;
		public final float fig2;
		public final float amplitudeFactor;

		public PitchFeatures(float medianCent, float amplitudeFactor) {
			this.medianCent = medianCent;
			this.amplitudeFactor = amplitudeFactor;
			fig1 = 0;
			fig2 = 0;
		}

		public PitchFeatures(float[] pitches) {
			Arrays.sort(pitches);

			if (pitches.length == 0 || pitches[pitches.length - 1] < 0) {
				// Empty pitches or made only of unvoiced data
				this.medianCent = Float.NaN;
				this.amplitudeFactor = Float.NaN;
				fig1 = Float.NaN;
				fig2 = Float.NaN;

				return;
			}

			// We have at least the last value being valid
			int start = pitches.length - 1;

			// Now perform a binary search
			int left = 0;
			int right = start - 1;
			while(left <= right) {
				// assume left + right will not overflow
				final int mid = (left + right) / 2;
				if (pitches[mid] < 0) {
					// Everything before mid is invalid
					left = mid + 1;
				} else {
					start = mid;
					right = mid - 1;
				}
			}

			int len = pitches.length - start;

			// Use nearest-rank quartile
			float p25 = pitches[start + ((len + 3) / 4)];
			float p75 = pitches[start + ((3*len + 3) / 4)];
			medianCent = 1200.f * (float)(Math.log(pitches[start + (len + 1) / 2]) / Math.log(2.0));
			// Try to get a value comparable in amplitude to medianCent as required by k-Means
			// Using the interquartile ratio here makes it like doing a delta in log domain
			//amplitudeFactor = medianCent * (p75 / p25);
			amplitudeFactor = p75 / p25;
			this.fig1 = p25;
			this.fig2 = p75;
		}

		public PitchFeatures(PitchFeatures o) {
			medianCent = o.medianCent;
			amplitudeFactor = o.amplitudeFactor;
			fig1 = o.fig1;
			fig2 = o.fig2;
		}

		// Computes the barycenter of all points pertaining to the specified cluster
		public PitchFeatures(ArrayList<PitchFeatures> points, int[] assignments, int cluster) {
			float sumMeanHz = 0;
			float sumAmpHz = 0;
			int numPoints = 0;

			int i;
			for (i = 0; i < assignments.length; i++) {
				if (assignments[i] != cluster) {
					continue;
				}
				PitchFeatures point = points.get(i);
				sumMeanHz += point.medianCent;
				sumAmpHz += point.amplitudeFactor;
				numPoints++;
			}
			if (numPoints > 0) {
				medianCent = sumMeanHz / numPoints;
				amplitudeFactor = sumAmpHz / numPoints;
			} else {
				medianCent = Float.NEGATIVE_INFINITY;
				amplitudeFactor = Float.NEGATIVE_INFINITY;
			}
			fig1 = 0;
			fig2 = 0;
		}

		public boolean invalid() {
			return Float.isNaN(medianCent);
		}

		public float distanceSquared(PitchFeatures o) {
			// Make min and max weigh more
			float dMedian = medianCent - o.medianCent;
			float dAmp = amplitudeFactor - o.amplitudeFactor;
			return dMedian * dMedian; // + dAmp * dAmp;
		}

		public static class PitchStatistics {
			public final float uMed, sMed;
			public final float uAmp, sAmp;

			private PitchStatistics(float uMed, float sMed, float uAmp, float sAmp) {
				this.uMed = uMed;
				this.sMed = sMed;
				this.uAmp = uAmp;
				this.sAmp = sAmp;
			}
		}

		public static PitchStatistics stats(ArrayList<PitchFeatures> dataset) {
			if (dataset.isEmpty()) {
				return new PitchStatistics(0, 0, 0, 0);
			}

			float uMed = 0, sMed = 0;
			float uAmp = 0, sAmp = 0;

			int count = dataset.size();

			for (PitchFeatures p : dataset) {
				uMed += p.medianCent;
				uAmp += p.amplitudeFactor;
			}
			uMed /= count;
			uAmp /= count;

			for (PitchFeatures p : dataset) {
				float diffMedian = p.medianCent - uMed;
				float diffAmp = p.amplitudeFactor - uAmp;
				sMed += diffMedian * diffMedian;
				sAmp += diffAmp * diffAmp;
			}
			sMed = (float)Math.sqrt(sMed / count);
			sAmp = (float)Math.sqrt(sAmp / count);

			return new PitchStatistics(uMed, sMed, uAmp, sAmp);
		}

		public static ArrayList<PitchFeatures> normalize(ArrayList<PitchFeatures> dataset, PitchStatistics stats) {
			if (dataset.isEmpty()) {
				return new ArrayList<>();
			}

			ArrayList<PitchFeatures> ret = new ArrayList<>(dataset.size());
			for (PitchFeatures p : dataset) {
				float newMed, newAmp;
				if (stats.sMed == 0) {
					newMed = 0;
				} else {
					newMed = (p.medianCent - stats.uMed) / stats.sMed;
				}
				if (stats.sAmp == 0) {
					newAmp = 0;
				} else {
					newAmp = (p.amplitudeFactor - stats.uAmp) / stats.sAmp;
				}
				ret.add(new PitchFeatures(newMed, newAmp));
			}
			return ret;
		}

		public static void denormalize(PitchFeatures[] dataset, PitchStatistics stats) {
			if (dataset.length == 0) {
				return;
			}

			for (int i = 0; i < dataset.length; i++) {
				PitchFeatures p = dataset[i];
				float newMed, newAmp;
				newMed = p.medianCent * stats.sMed + stats.uMed;
				newAmp = p.amplitudeFactor * stats.sAmp + stats.uAmp;
				dataset[i] = new PitchFeatures(newMed, newAmp);
			}
		}
	}
	*/

	private final ArrayList<PitchFeatures> _dataset = new ArrayList<>();

	public boolean addSeries(float[] pitches) {
		PitchFeatures features = new PitchFeatures(pitches);
		if (features.invalid()) {
			return false;
		} else {
			_dataset.add(features);
			return true;
		}
	}

	/**
	 * Runs the K-Means clustering algorithm.
	 *
	 * @param k             Number of clusters to generate
	 * @param maxIterations Maximum times to loop (prevents infinite loops if floating point errors occur)
	 * @return List of identified clusters
	 */
	public KMeansResult fit(int k, int maxIterations) {
		if (k <= 0) {
			throw new IllegalArgumentException("k must be strictly positive");
		}

		int nSamples = _dataset.size();

		int[] assignments = new int[nSamples];
		PitchFeatures[] centroids = new PitchFeatures[k];

		if (nSamples < k) {
			// Not enough data points for the clustering: set one centroid per data point
			// and complete with invalid points
			for (int i = 0; i < nSamples; i++) {
				assignments[i] = i;
				centroids[i] = _dataset.get(i);
			}
			float[] fakePitches = new float[]{};
			for (int i = nSamples; i < k; i++) {
				centroids[i] = new PitchFeatures(fakePitches);
			}

			return new KMeansResult(centroids, assignments);
		}

		StringBuilder debug = new StringBuilder();
		for(PitchFeatures p : _dataset) {
			debug.append("(");
			debug.append(p.medianCent);
			debug.append(", ");
			debug.append(p.amplitudeFactor);
			/*
			debug.append(", ");
			debug.append(p.fig1);
			debug.append(", ");
			debug.append(p.fig2);
			 */
			debug.append("),\n");
		}

		// Normalize
		/*
		PitchFeatures.PitchStatistics stats = PitchFeatures.stats(_dataset);
		ArrayList<PitchFeatures> dataset = PitchFeatures.normalize(_dataset, stats);
		*/
		ArrayList<PitchFeatures> dataset = _dataset;

		// 1. K-means++ initial selection
		{
			float[] minDist = new float[nSamples];
			Random random = new Random();

			// 1a. Pick first centroid randomly
			centroids[0] = new PitchFeatures(dataset.get(random.nextInt(nSamples)));
			// Track squared distance from each point to its nearest selected centroid
			for (int i = 0; i < nSamples; i++) {
				minDist[i] = centroids[0].distanceSquared(dataset.get(i));
			}
			// 1b. Pick remaining k - 1 centroids with probability proportional to D(x)^2
			for (int c = 1; c < k; c++) {
				float totalWeight = 0.f;
				for (int i = 0; i < nSamples; i++) {
					totalWeight += minDist[i];
				}

				// Weighted random selection
				float threshold = random.nextFloat() * totalWeight;

				int centroidIdx = nSamples - 1;
				float cumulativeWeight = 0.f;
				for (int i = 0; i < nSamples; i++) {
					cumulativeWeight += minDist[i];
					if (cumulativeWeight >= threshold) {
						centroidIdx = i;
						break;
					}
				}

				centroids[c] = new PitchFeatures(dataset.get(centroidIdx));

				// Update minimum squared distances for remaining points
				if (c < k - 1) {
					for (int i = 0; i < nSamples; i++) {
						float dist = centroids[0].distanceSquared(dataset.get(i));
						if (dist < minDist[i]) {
							minDist[i] = dist;
						}
					}
				}
			}
		}

		// 2. Iteration phase
		int iter = 0;
		while (iter < maxIterations) {
			boolean changed = false;
			iter++;

			// Step A: Assign each point to the nearest cluster centroid
			for (int i = 0; i < nSamples; i++) {
				PitchFeatures point = dataset.get(i);
				int bestCluster = -1;
				double minDistance = Double.POSITIVE_INFINITY;

				for (int c = 0; c < k; c++) {
					float dist = point.distanceSquared(centroids[c]);
					if (dist < minDistance) {
						minDistance = dist;
						bestCluster = c;
					}
				}

				if (assignments[i] != bestCluster) {
					assignments[i] = bestCluster;
					changed = true; // Convergence check
				}
			}
			if (!changed) {
				break;
			}

			// Step B: Recalculate centroids as the mean of all points in the cluster
			for (int c = 0; c < k; c++) {
				centroids[c] = new PitchFeatures(dataset, assignments, c);
			}
		}

		/*
		PitchFeatures.denormalize(centroids, stats);
		*/

		return new KMeansResult(centroids, assignments);
	}
}
