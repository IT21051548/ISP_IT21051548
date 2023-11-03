import pandas as pd
import numpy as np
from pandas import ExcelWriter
from pandas import ExcelFile
import re
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score
from sklearn.metrics import classification_report
from sklearn.naive_bayes import GaussianNB
from sklearn import metrics
import matplotlib.pyplot as plt
import wx
from sklearn import svm
import webbrowser
from sklearn.ensemble import RandomForestClassifier
import seaborn as sns
from yellowbrick.classifier import ClassificationReport
from sklearn.metrics import confusion_matrix, accuracy_score, roc_auc_score, roc_curve
from sklearn import preprocessing

# Extract one characteristic
def extract_feature_usertest(url):
    # Length of the url
    l_url = len(url)
    if l_url > 54:
        length_of_url = 1
    else:
        length_of_url = 0

    # does url has http
    if ("http://" in url) or ("https://" in url):
        http_has = 1
    else:
        http_has = 0

    # does url has suspicious characters
    if ("@" in url) or ("//" in url):
        suspicious_char = 1
    else:
        suspicious_char = 0

    # Prefix/suffix
    if "-" in url:
        prefix_suffix = 1
    else:
        prefix_suffix = 0

    # Number of dots in url
    if "." in url:
        count = len(url.split('.')) - 1
        if count > 5:
            dots = 0
        else:
            dots = 1
    else:
        dots = 0

    # Number of slash in url
    if "/" in url:
        count = len(url.split('/')) - 1
        if count > 5:
            slash = 0
        else:
            slash = 1
    else:
        slash = 0

    # does Url has phishing terms
    if ("secure" in url) or ("websrc" in url) or ("ebaysapi" in url) or ("signin" in url) or ("banking" in url) or (
            "confirm" in url) or ("login" in url):
        phis_term = 1
    else:
        phis_term = 0

    # Length of the subdomain
    it = url.index("//") + 2
    j = url.index(".")
    c = j - it
    if c > 5:
        sub_domain = 0
    else:
        sub_domain = 1

    # does Url contains IP address
    if re.match(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", url):
        ip_contain = 1
    else:
        ip_contain = 0

    return length_of_url, http_has, suspicious_char, prefix_suffix, dots, slash, phis_term, sub_domain, ip_contain

# Extract testing characterist
def extract_feature_test(url, output):
    # Length of the url
    l_url = len(url)
    if l_url > 54:
        length_of_url = 1
    else:
        length_of_url = 0

    # does url has http
    if ("http://" in url) or ("https://" in url):
        http_has = 1
    else:
        http_has = 0

    # does url has suspicious char
    if ("@" in url) or ("//" in url):
        suspicious_char = 1
    else:
        suspicious_char = 0

    # Prefix / suffix
    if "-" in url:
        prefix_suffix = 1
    else:
        prefix_suffix = 0

    # Number of dots
    if "." in url:
        count = len(url.split('.')) - 1
        if count > 5:
            dots = 0
        else:
            dots = 1
    else:
        dots = 0

    # Number of slash
    if "/" in url:
        count = len(url.split('/')) - 1
        if count > 5:
            slash = 0
        else:
            slash = 1
    else:
        slash = 0

    # does Url has phishing terms
    if ("secure" in url) or ("websrc" in url) or ("ebaysapi" in url) or ("signin" in url) or ("banking" in url) or (
            "confirm" in url) or ("login" in url):
        phis_term = 1
    else:
        phis_term = 0

    # Length of the subdomain
    it = url.index("//") + 2
    j = url.index(".")
    c = j - it
    if c > 5:
        sub_domain = 0
    else:
        sub_domain = 1

    # does Url contains IP address
    if re.match(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", url):
        ip_contain = 1
    else:
        ip_contain = 0

    # Output
    yn = output

    return yn, length_of_url, http_has, suspicious_char, prefix_suffix, dots, slash, phis_term, sub_domain, ip_contain

# Extract training characterist
def extract_feature_train(url, output):
    # Length of the url
    l_url = len(url)
    if l_url > 54:
        length_of_url = 1
    else:
        length_of_url = 0

    # does url has http
    if ("http://" in url) or ("https://" in url):
        http_has = 1
    else:
        http_has = 0

    # does url has suspicious char
    if ("@" in url) or ("//" in url):
        suspicious_char = 1
    else:
        suspicious_char = 0

    # Prefix / suffix
    if "-" in url:
        prefix_suffix = 1
    else:
        prefix_suffix = 0

    # Number of the dots
    if "." in url:
        count = len(url.split('.')) - 1
        if count > 5:
            dots = 0
        else:
            dots = 1
    else:
        dots = 0

    # Number of the slash
    if "/" in url:
        count = len(url.split('/')) - 1
        if count > 5:
            slash = 0
        else:
            slash = 1

    else:
        slash = 0

    # does Url has phishing terms
    if ("secure" in url) or ("websrc" in url) or ("ebaysapi" in url) or ("signin" in url) or ("banking" in url) or (
            "confirm" in url) or ("login" in url):
        phis_term = 1
    else:
        phis_term = 0

    # Length of the subdomain
    it = url.index("//") + 2
    j = url.index(".")
    c = j - it
    if c > 5:
        sub_domain = 0
    else:
        sub_domain = 1

    # does Url contains IP address
    if re.match(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", url):
        ip_contain = 1
    else:
        ip_contain = 0

    # Output
    yn = output

    return yn, length_of_url, http_has, suspicious_char, prefix_suffix, dots, slash, phis_term, sub_domain, ip_contain

# Importing train data
def importdata_train():
    balance_data = pd.read_csv('feature_train.csv', sep=',', header=1, usecols=range(1, 11), encoding='utf-8')

    # Printing dataset shape
    print("Dataset Length: ", len(balance_data))
    print("Dataset Shape: ", balance_data.shape)

    # Printing dataset observations
    print("Dataset: ", balance_data.head())
    return balance_data

# Importing test data
def importdata_test():
    balance_data = pd.read_csv('feature_test.csv', sep=',', header=1, usecols=range(1, 11), encoding='utf-8')

    # Printing dataset shape
    print("Dataset Length: ", len(balance_data))
    print("Dataset Shape: ", balance_data.shape)

    # Printing dataset observations
    print("Dataset: ", balance_data.head())
    return balance_data

# Spliting data into train and test
def splitdataset(balance_data):
    # Separating target variable
    X = balance_data.values[:, 1:10]
    Y = balance_data.values[:, 0]

    return X, Y

# Function to perform training with entropy
def train_using_entropy(X_train, y_train):
    # Decision tree with entropy
    clf_entropy = DecisionTreeClassifier(
        criterion="entropy", random_state=100,
        max_depth=2, min_samples_leaf=10)

    # Performing training
    clf_entropy.fit(X_train, y_train)
    return clf_entropy

# Function to make predictions
def prediction(X_test, clf_object):
    # Prediction on test with giniIndex
    y_pred = clf_object.predict(X_test)
    return y_pred

# Function to calculate accuracy
def cal_accuracy(y_test, y_pred):
    print("Confusion Matrix: ",
          confusion_matrix(y_test, y_pred))

    print("Accuracy : ",
          accuracy_score(y_test, y_pred) * 100)

    print("Report : ",
          classification_report(y_test, y_pred))

    return accuracy_score(y_test, y_pred) * 100

# ROC
def plot_roc_curve(fpr, tpr):
    plt.plot(fpr, tpr, color='orange', label='ROC')
    plt.plot([0, 1], [0, 1], color='darkblue', linestyle='--')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic (ROC) Curve')
    plt.legend()
    plt.show()

# Main function
def main():
    excel_file = 'training.xlsx'
    df = pd.DataFrame(pd.read_excel(excel_file))
    excel_file_test = 'test1.xlsx'
    df1 = pd.DataFrame(pd.read_excel(excel_file_test))

    a = []
    b = []
    a1 = []
    b1 = []
    for url in df['url']:
        a.append(url)

    for output in df['phishing']:
        b.append(output)

    for url1 in df1['url']:
        a1.append(url1)

    for output1 in df1['result']:
        b1.append(output1)

    c = []
    d = []
    for url1, output1 in zip(a, b):
        url = url1
        output = output1
        c.append(extract_feature_train(url, output))

    for url1, output1 in zip(a1, b1):
        url = url1
        output = output1
        d.append(extract_feature_test(url, output))

    df = pd.DataFrame(c,
                      columns=['r', 'length_of_url', 'http_has', 'suspicious_char', 'prefix_suffix', 'dots', 'slash',
                               'phis_term', 'sub_domain', 'ip_contain'])

    df.to_csv('feature_train.csv', sep=',', encoding='utf-8')

    df_test = pd.DataFrame(d,
                           columns=['r', 'length_of_url', 'http_has', 'suspicious_char', 'prefix_suffix', 'dots',
                                    'slash', 'phis_term', 'sub_domain', 'ip_contain'])

    df_test.to_csv('feature_test.csv', sep=',', encoding='utf-8')

    data_train = importdata_train()

    data_test = importdata_test()

    X, Y = splitdataset(data_train)
    X1, Y1 = splitdataset(data_test)

    Y = np.where(Y == 'yes', '1', Y)
    Y = np.where(Y == 'no', '0', Y)
    Y1 = np.where(Y1 == 'yes', '1', Y1)
    Y1 = np.where(Y1 == 'no', '0', Y1)

    model = RandomForestClassifier()
    model.fit(X, Y)

    class MainFrame(wx.Frame):

        def __init__(self, parent):
            wx.Frame.__init__(self, parent, id=wx.ID_ANY, title=wx.EmptyString, pos=wx.DefaultPosition,
                              size=wx.Size(500, 300), style=wx.DEFAULT_FRAME_STYLE | wx.TAB_TRAVERSAL)

            self.SetSizeHintsSz(wx.DefaultSize, wx.DefaultSize)

            bSizer3 = wx.BoxSizer(wx.VERTICAL)

            self.m_staticText2 = wx.StaticText(self, wx.ID_ANY, u"Enter URL", wx.DefaultPosition, wx.DefaultSize, 0)
            self.m_staticText2.Wrap(-1)
            bSizer3.Add(self.m_staticText2, 0, wx.ALL, 5)

            self.text1 = wx.TextCtrl(self, wx.ID_ANY, wx.EmptyString, wx.DefaultPosition, wx.DefaultSize, 0)
            bSizer3.Add(self.text1, 0, wx.ALL, 5)

            self.m_button2 = wx.Button(self, wx.ID_ANY, u"Predict", wx.DefaultPosition, wx.DefaultSize, 0)
            bSizer3.Add(self.m_button2, 0, wx.ALL, 5)

            self.m_staticText3 = wx.StaticText(self, wx.ID_ANY, u"Prediction Result", wx.DefaultPosition, wx.DefaultSize,
                                               0)
            self.m_staticText3.Wrap(-1)
            bSizer3.Add(self.m_staticText3, 0, wx.ALL, 5)

            self.text2 = wx.TextCtrl(self, wx.ID_ANY, wx.EmptyString, wx.DefaultPosition, wx.DefaultSize, 0)
            bSizer3.Add(self.text2, 0, wx.ALL, 5)

            self.SetSizer(bSizer3)
            self.Layout()

            self.Centre(wx.BOTH)

            # Connect Events
            self.m_button2.Bind(wx.EVT_BUTTON, self.onPredict)

        def __del__(self):
            pass

        def onPredict(self, event):
            url = self.text1.GetValue()
            url_input = [extract_feature_usertest(url)]
            url_output = model.predict(url_input)
            if url_output == '1':
                self.text2.SetValue("Malicious")
            else:
                self.text2.SetValue("Not Malicious")

    class App(wx.App):

        def OnInit(self):
            frame = MainFrame(None)
            self.SetTopWindow(frame)
            frame.Show(True)
            return True

    app = App(0)
    app.MainLoop()

if __name__ == '__main__':
    main()
