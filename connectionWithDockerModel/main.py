from __future__ import print_function
#from mitmproxyscanandread import scancoomandsfromfile
import base64
import json
import pickle
import sklearn

import numpy as np
import requests
import cv2



# The server URL specifies the endpoint of your server running the ResNet
# model with the name "xss_model & sql_model" and using the predict interface.
SERVER_URL_XSS = 'http://localhost:8501/v1/models/xss:predict'
SERVER_URL_SQL = 'http://localhost:8500/v1/models/sql:predict'


# Convert to ASCII
def convert_to_ascii(sentence):
    sentence_ascii = []

    for i in sentence:

        """Some characters have values very big e.d 8221 adn some are chinese letters
        I am removing letters having values greater than 8222 and for rest greater 
        than 128 and smaller than 8222 assigning them values so they can easily be normalized"""

        if (ord(i) < 8222):  # ” has ASCII of 8221

            if (ord(i) == 8217):  # ’  :  8217
                sentence_ascii.append(134)

            if (ord(i) == 8221):  # ”  :  8221
                sentence_ascii.append(129)

            if (ord(i) == 8220):  # “  :  8220
                sentence_ascii.append(130)

            if (ord(i) == 8216):  # ‘  :  8216
                sentence_ascii.append(131)

            if (ord(i) == 8217):  # ’  :  8217
                sentence_ascii.append(132)

            if (ord(i) == 8211):  # –  :  8211
                sentence_ascii.append(133)

            """
            If values less than 128 store them else discard them
            """
            if (ord(i) <= 128):
                sentence_ascii.append(ord(i))

            else:
                pass

    zer = np.zeros((10000))

    for i in range(len(sentence_ascii)):
        zer[i] = sentence_ascii[i]

    zer.shape = (100, 100)

    #     plt.plot(image)
    #     plt.show()
    return zer


def make_prediction_xss(instances):
    data = json.dumps({"signature_name": "serving_default", "instances": instances.tolist()})
    headers = {"content-type": "application/json"}
    json_response = requests.post(SERVER_URL_XSS, data=data, headers=headers)
    predictions = json.loads(json_response.text)['predictions']
    return predictions


def make_prediction_sql(instances):
    data = json.dumps({"signature_name": "serving_default", "instances": instances.tolist()})
    headers = {"content-type": "application/json"}
    json_response = requests.post(SERVER_URL_SQL, data=data, headers=headers)
    print(json_response)
    predictions = json.loads(json_response.text)['predictions']
    return predictions

def clean_data(input_val):

    input_val=input_val.replace('\n', '')
    input_val=input_val.replace('%20', ' ')
    input_val=input_val.replace('=', ' = ')
    input_val=input_val.replace('((', ' (( ')
    input_val=input_val.replace('))', ' )) ')
    input_val=input_val.replace('(', ' ( ')
    input_val=input_val.replace(')', ' ) ')
    input_val=input_val.replace('1 ', 'numeric')
    input_val=input_val.replace(' 1', 'numeric')
    input_val=input_val.replace("'1 ", "'numeric ")
    input_val=input_val.replace(" 1'", " numeric'")
    input_val=input_val.replace('1,', 'numeric,')
    input_val=input_val.replace(" 2 ", " numeric ")
    input_val=input_val.replace(' 3 ', ' numeric ')
    input_val=input_val.replace(' 3--', ' numeric--')
    input_val=input_val.replace(" 4 ", ' numeric ')
    input_val=input_val.replace(" 5 ", ' numeric ')
    input_val=input_val.replace(' 6 ', ' numeric ')
    input_val=input_val.replace(" 7 ", ' numeric ')
    input_val=input_val.replace(" 8 ", ' numeric ')
    input_val=input_val.replace('1234', ' numeric ')
    input_val=input_val.replace("22", ' numeric ')
    input_val=input_val.replace(" 8 ", ' numeric ')
    input_val=input_val.replace(" 200 ", ' numeric ')
    input_val=input_val.replace("23 ", ' numeric ')
    input_val=input_val.replace('"1', '"numeric')
    input_val=input_val.replace('1"', '"numeric')
    input_val=input_val.replace("7659", 'numeric')
    input_val=input_val.replace(" 37 ", ' numeric ')
    input_val=input_val.replace(" 45 ", ' numeric ')

    return input_val
def xss_proccesor(req):
    list_proxy = [req]
    #print(list_proxy)

    for l in list_proxy:
        if(len(l)>0):
            sentences2 = [l]
            print(sentences2)
            arr2 = np.zeros((len(sentences2), 100, 100))

            for i in range(len(sentences2)):
                image = convert_to_ascii(sentences2[i])
                x = np.asarray(image, dtype='float')
                image = cv2.resize(x, dsize=(100, 100), interpolation=cv2.INTER_CUBIC)
                image /= 128
                arr2[i] = image
            data2 = arr2.reshape(arr2.shape[0], 100, 100, 1)
            data2.shape
            res = make_prediction_xss(data2)
            if (res[0][0]>0.8):
                print(res[0][0])
                print('XSS ATTACK')
            else:
                print(res[0][0])
                print('OK')
    return res[0][0]


def predict_sqli_attack(req):

    myvectorizer = pickle.load(open('connectionWithDockerModel/vectorizer_cnn', 'rb'))
    beautify = ''
    for i in range(20):
        beautify += "="

    print(beautify)
    input_val = req
    print(beautify)

    if input_val == '0':
        repeat = False

    input_val = [input_val]

    input_val = myvectorizer.transform(input_val).toarray()

    result = make_prediction_sql(input_val)

    print(beautify)



    if result[0][0] > 0.8:
        print(result[0][0])
        print("ALERT :::: This can be SQL injection: ",req)


    elif result[0][0] <= 0.8:
        print(result[0][0])
        print("It seems to be safe: ",req)

    print(beautify)

    return result[0][0]
def main():

    predict_sqli_attack()
    xss_proccesor()


if __name__ == '__main__':
    main()
