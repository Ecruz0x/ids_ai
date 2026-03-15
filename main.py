import joblib
from netsniffer import capture_and_flow_control as capture
import warnings
from collections import Counter


warnings.filterwarnings("ignore", category=UserWarning)



model = joblib.load("models/bestmodel.pkl")

def flow_verify(details):
    prediction = model.predict([details])
    if prediction != ['Benign']:
        print(prediction)



capture("lo", flow_verify)
