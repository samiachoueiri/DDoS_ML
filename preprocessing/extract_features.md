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
| 4. Replay | Build attack-only PCAPs, replay them into the pipeline, compare | ~1 h to build, then the replay time |

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

## Part 4: replay attack traffic into the pipeline

This replays the CICDDoS2019 attack flows, without the `BENIGN` and `unknown`
ones, into the P4 pipeline. The pipeline then extracts the same features online
that the notebook extracts offline.

Two scripts in `preprocessing/`:

| Script | Runs on | What it does |
|---|---|---|
| `make_attack_replay_pcap.py` | this machine | Writes `<name>_attack.pcap` (packets of the attack flows only) and `<name>_ground_truth.csv` (one row per flow: 5-tuple, label, `flow_start_us`, packets written) for each PCAP |
| `replay_attacks.sh` | server1 | Rewrites the MACs of each `*_attack.pcap` and replays it with tcpreplay |

Flows are split and labelled exactly as in the notebook, and each kept flow
keeps all its packets with their original timestamps. Running the offline
extractor on `<name>_attack.pcap` gives the same rows as the training CSV for
those flows. Flows with fewer than N packets are left out, since they are never
training rows.

### 9. Build the attack-only PCAPs

In `cicddos2019_cached_label_extraction.ipynb`, run the setup cells, the
Configuration cell, "Load official CSV labels" and Step 1 (for `pcap_files`).
Then add a cell and test it on one file:

```python
import importlib
import make_attack_replay_pcap as replay
replay = importlib.reload(replay)

REPLAY_DIR = Path("./replay") / DAY

replay.build_replay_pcap(PCAP_DIR / "SAT-03-11-2018_0.pcap", REPLAY_DIR, labeler,
                         n_packets=N_PACKETS, flow_timeout=FLOW_TIMEOUT)
```

The output lists the flows kept per label. Only attack labels should appear.
Then process all the files (about 20 s per file):

```python
results = replay.build_replay_batch(pcap_files, REPLAY_DIR, labeler,
                                    n_packets=N_PACKETS, flow_timeout=FLOW_TIMEOUT)
pd.DataFrame(results).to_csv(REPLAY_DIR / f"replay_log_n{N_PACKETS}.csv", index=False)
```

The files go to `preprocessing/replay/03-11/`.

Options:

| Notebook argument | Terminal flag | Default | Meaning |
|---|---|---|---|
| `n_packets` | `--n-packets` | 5 | Same N as the P4 program |
| `flow_timeout` | `--flow-timeout` | 120 | Same as the feature extraction |
| `first_n_only=True` | `--first-n-only` | off | Write only the first N packets of each flow (smaller files, lower replay rate) |
| `exclude_labels` | `--exclude-labels` | `BENIGN unknown` | Labels to leave out |
| `skip_existing` (batch only) | n/a | True | Skip PCAPs whose `ground_truth.csv` already exists |

Without the notebook, the script loads the label CSVs itself. This is slower:

```bash
cd ~/DDoS_ML/preprocessing
python3 make_attack_replay_pcap.py \
  --pcap-file /home/ubuntu/datasets/CICDDoS2019/PCAP-03-11/*.pcap \
  --label-csv-dir /home/ubuntu/datasets/CICDDoS2019/CSV-03-11/03-11 \
  --out-dir replay/03-11 --n-packets 5
```

### 10. Copy the files to server1

From the FABRIC notebook:

```python
from pathlib import Path
server1.upload_file('/home/ubuntu/DDoS_ML/preprocessing/replay_attacks.sh', 'replay_attacks.sh')
server1.execute('mkdir -p attacks && chmod +x replay_attacks.sh')
for p in sorted(Path('/home/ubuntu/DDoS_ML/preprocessing/replay/03-11').glob('*_attack.pcap')):
    server1.upload_file(str(p), f'attacks/{p.name}')
```

### 11. Replay

On server2, start the pipeline:

```bash
sudo dpdk/examples/pipeline/build/pipeline -c 0x1F -- -s /home/ubuntu/features/features.cli
```

On server1:

```bash
sudo ./replay_attacks.sh -d attacks                 # wait between files (default)
sudo ./replay_attacks.sh -d attacks -y              # no waiting, back-to-back
sudo ./replay_attacks.sh -d attacks -m 00:00:00:00:00:22 -i enp8s0np0   # other MAC / interface
```

| Flag | Default | Meaning |
|---|---|---|
| `-d DIR` | `.` | Folder containing the `*_attack.pcap` files |
| `-i IFACE` | `enp7s0np0` | Interface to send on |
| `-s SRC_MAC` | `00:00:00:00:00:01` | Source MAC |
| `-m DST_MAC` | `00:00:00:00:00:21` | Destination MAC |
| `-y` | off | Don't wait between files |

For each file, the script rewrites the MACs into a temporary copy, replays it
at the original timing, and deletes the copy. The originals are not changed.
Everything tcprewrite and tcpreplay print goes to
`replay_<date>_<time>.log`.

After each file, it waits for Enter. In that time, on server2:

1. Save the registers: `python3 features/telnet.py`. Name the CSV after the
   PCAP so you can match them later.
2. Restart the pipeline. The P4 program has no flow timeout, so registers from
   the previous file would otherwise stay in place and use up the 2^20 flow
   slots.

Check `Failed packets` in tcpreplay's output for each file. If it isn't 0, the
replay rate was too high. Rebuild the PCAPs with `first_n_only=True`.

### 12. Compare online with offline

```bash
cd ~/DDoS_ML/validation
python3 extract_selected_features.py \
  --pcap-file ../preprocessing/replay/03-11/SAT-03-11-2018_0_attack.pcap \
  --online-file <online>.csv
```

To check the classifier's predictions later, `<name>_ground_truth.csv` gives
the true label of each flow by 5-tuple.
