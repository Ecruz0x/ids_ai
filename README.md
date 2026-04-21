# Network Intrusion Detection (ML)

ML school project to detect network attacks from traffic data.

the notebook:
- Loads multiple CSV files from `data/`
- Cleans and reduces features
- Encodes protocol (TCP=0, UDP=1)
- Trains a `HistGradientBoostingClassifier` model
- Splits data (70/30) and evaluates performance

Detects:
- Benign
- DoS
- Port Scan
- Heartbleed
- etc.

## Run

Install deps:
```shell
pip install pandas numpy scikit-learn matplotlib joblib
```

Put your data in:
`data/`

Run the notebook. the trained model will be saved in `/model` which will be used to detect malicious traffic and save logs to a sql database.

## Notes
- Add the Database credentials inside `netsniffer.py`
- Add your data in a folder called `data/`
- Model works with large datasets
- Easy to modify / extend

## Contribution
Email me at : `abdelhaqnaciri0@gmail.com`
