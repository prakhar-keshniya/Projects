import pandas as pd
import datetime
import smtplib

# Enter your autentication informaton.
GMAIL_ID = 'prakhar.link@gmail.com'
GMAIL_PSWD = 'qmhajyijafeumizp'

def sendmessage(to,sub,msg):
    print(f"Email to {to} send with subject: {sub} and message {msg}")
    s = smtplib.SMTP_SSL('smtp.gmail.com',465)
    # s.starttls()                                        # It is use for to make our secure connection one using TLS(Transport Layer Security) encryption.
    s.login(GMAIL_ID,GMAIL_PSWD)
    s.sendmail(GMAIL_ID,to,f"Subject: {sub}\n\n{msg}")
    s.quit()



if __name__ == "__main__": 
    df = pd.read_excel("Project 16-Birthday.xlsx")
    df["Year"] = df["Year"].astype(str)

    # print(df)
    today = datetime.datetime.now().strftime("%d-%m")       # strftime() :- It is use to take the real date and time.
    YearNow = datetime.datetime.now().strftime("%Y")        # strftime() :- It is use to take the real year.
    # print(today)
    writInd = []
    for index,item in df.iterrows():                        # iterrows():- It means it read row by row one by one.
        # print(index ,item["Date"])
        bday = item["Date"].strftime("%d-%m")
        if (today == bday) and (YearNow not in str(item["Year"])):
            sendmessage(item["Send to"],"Birthday wishes",item["Message"])
            writInd.append(index)

    # print(writInd)
    for i in writInd:
        yr = df.loc[i,'Year']                               # loc[row_label, column_label] = select data from a DataFrame using row labels and column names.
        df.loc[i,'Year'] = str(yr) + ',' + str(YearNow)
        # print(df)
        print(df.loc[i,'Year']) 


    # print(df) 
    df.to_excel("Project 16-Birthday.xlsx",index=False)
