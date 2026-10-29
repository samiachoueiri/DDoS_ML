# Re-extracting features and retraining

The extractors now output timing features (`duration`, `iat_min`, `iat_max`,
`iat_mean`, `iat_std`) in integer **microseconds**, the same unit the P4 data
plane uses, so no conversion is needed between training and online inference.
`packets_per_second` and `bytes_per_second` are still per second.

Training CSVs made before this change are in seconds. Everything downstream
(feature CSVs, models, P4 rules) has to be regenerated.

The steps are ordered so that the long benign (MAWI) extraction runs last and
can be left unattended. Retraining needs both the attack and benign features,
so Part 3 waits until MAWI finishes.

| Part | Steps | Time |
|---|---|---|
| 1. Interactive | Prepare, extract attack features, check them | A few hours, with some waiting |
| 2. Unattended | Extract benign features (MAWI) | ~10 h for N = 3, 4, 5 (~3 h for N = 5 only) |
| 3. After MAWI | Check, retrain, regenerate rules, validate online | Depends on training |

## Part 1: interactive steps

### 1. Before you start

```bash
cd ~/DDoS_ML/validation
python3 make_test_pcap.py --check            # should print PASS for n=3,4,5
cd ~/DDoS_ML/preprocessing
mv features_out features_out_seconds_backup  # keep the old CSVs (seconds); ~3.4 GB
mkdir features_out
```

Moving the old folder aside matters for two reasons:

- **The notebook would skip the work.** It has `SKIP_EXISTING = True`, so it
  skips any PCAP that already has an output file.
- **Old and new files are easy to mix up.** They have the same column names, and
  nothing would warn you.

### 2. Attack features (CICDDoS2019)

Open `preprocessing/cicddos2019_cached_label_extraction.ipynb`.

1. **Restart the kernel**, so it loads the updated extractor and not the old one
   kept in memory.
2. **Configuration cell**: set `N_PACKETS = 5`, and leave everything else as it
   is.
3. Run the cell that loads the label CSVs. It's slow, but you only need to run
   it once per kernel.
4. Optional: run "Process one PCAP" and check that `iat_max` values are whole
   numbers such as `20000`, not `2e-05`.
5. Run **Step 1 → Step 3** to process all the PCAPs, then Step 4 for the batch
   log.
6. **Step 6 (combine)**: `batch_dir` is hardcoded to
   `/home/ubuntu/DDoS_ML/preprocessing/features_out/03-11/03-11/batch`. That
   still matches the new output folder, so you don't need to change it.
7. Copy the combined file to the name the training notebooks load:
   ```bash
   cp features_out/03-11/03-11/batch/combined_features_n5.csv features_out/attack_features_n5.csv
   ```
8. Repeat from step 2 with `N_PACKETS = 3` and then `4`, if you need them. You
   don't need to reload the labels while the kernel stays alive.

### 3. Check the attack CSV

```bash
cd ~/DDoS_ML/preprocessing/features_out
head -3 attack_features_n5.csv | cut -d, -f7,15-18
```

`duration`, `iat_min` and `iat_max` should be whole numbers in µs, for example
`53` and not `5.29e-05`.

## Part 2: start the long run and leave it

### 4. Benign features (MAWI)

```bash
cd ~/DDoS_ML/preprocessing
nohup ./mawi_extraction.sh > mawi_extraction.log 2>&1 &
```

This runs N = 3, 4 and 5 one after another and writes
`features_out/benign_features_n{3,4,5}.csv`. `nohup` keeps it running after you
close the terminal or disconnect.

If you only need N = 5 for now, edit the script to `for n in 5; do` first.

To check progress:

```bash
tail -3 ~/DDoS_ML/preprocessing/mawi_extraction.log
```

It's done when the log shows `=== Finished n=5 ... exit code 0 ===`.

## Part 3: after MAWI finishes

### 5. Check the benign CSV against the attack CSV

```bash
cd ~/DDoS_ML/preprocessing/features_out
head -3 benign_features_n5.csv | cut -d, -f7,15-18
diff <(head -1 benign_features_n5.csv) <(head -1 attack_features_n5.csv | cut -d, -f1-25)
```

The `diff` should print nothing. The attack file has 4 extra columns at the end,
from the labeled extractor.

### 6. Retrain

In `training/`, restart each notebook's kernel and run it from the top, in this
order:

1. `feature_selection.ipynb`
2. `training_binary.ipynb` / `training_multiclass.ipynb`
3. `training_knn.ipynb`
4. `training_knn_reduced.ipynb`, which exports the KNN centroid CSVs

Check for any **fixed numbers that assume seconds**, such as a filter like
`duration < 1`, a clip value, or hand-set bins for `iat_*` or `duration`. Those
would need to be multiplied by 1,000,000. Values the code calculates itself
(scalers, tree thresholds, centroids) adjust automatically.

### 7. Regenerate the deployment files

- Generate the P4 rule files (`rules_*.txt`) and the KNN centroids again from
  the new models. All IAT and duration thresholds will now be whole µs values,
  so no conversion is needed.
- Move the old models in `training/models/` aside so they aren't loaded by
  mistake.

### 8. Check online again

After you deploy the new rules, replay the test PCAP and run:

```bash
cd ~/DDoS_ML/validation
python3 extract_selected_features.py --pcap-file test_data_1flow/test_flows.pcap \
  --online-file test_data_1flow/online_selected_n5.csv
```

Once the new results look right, you can delete
`features_out_seconds_backup`.
