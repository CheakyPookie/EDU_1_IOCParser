import requests
import re
import os

patterns = {'URLs':'\s[\w]{3,}:\/\/[\S]{16,}\s',
            'IPs':'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\:(?:6553[5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[0-9]{1,4}))?',
            'Domains':'\s(?:[a-zA-Z0-9\-]{2,}\.)+',
            'MD5':'\s([0-9a-fA-F]{32})\s',
            'SHA1':'\s([0-9a-fA-F]{40})\s',
            'SHA256':'\s([0-9a-fA-F]{64})\s'}

url = 'https://habr.com/ru/companies/f_a_c_c_t/news/792672/'

def TldsToDomain():
    with open('tlds.txt','r') as file:
        tlds = file.read()
        tlds = tlds.replace("\n","|")
        patterns['Domains'] = patterns['Domains'] + '(?:' + tlds + ')\s' 

def InfoToFile(filename, info):
    result = 0
    unqiue_elements = []
    with open( './report/' + filename + '.txt','w') as file:
        for j in range(len(info)):
            if j not in unqiue_elements:
                info[j] = re.sub('\s','',info[j])
                file.write(info[j])
                file.write('\n')
                unqiue_elements.append(str(info[j]))  
    with open('./report/' + 'IOCs' + '.txt','a+') as file:
        for j in unqiue_elements:
            file.write(j)
            file.write('\n')
    return(result)

def IocParser():
    result = 0
    r = requests.get(url)
    text = r.text

    buffer = (re.split('(индикаторы компрометации)|(ioc)',text,1,re.I))
    if len(buffer) > 1:
        text = buffer[3]
        text = (re.split('</div>',text))[0]
        text = re.sub('(<p>)|(<br/>)','\n\n',text)    
        text = re.sub('<.*?>','',text)
        text = re.sub('hxxp','http',text,0,re.I)
        text = text.replace('[.]','.')

        if not os.path.isdir('report'):
            os.mkdir('./report')
        file = open('IOCs' + '.txt','w')   
        file.close() 
                        
        for i in patterns:
            re_str = re.findall(patterns[i], text)
            if i in {'MD5','SHA1','SHA256'}:
                InfoToFile('Hash'+'_'+i,re_str)
            else:
                InfoToFile(i,re_str)
    
    return(result)

if __name__ == '__main__':
    TldsToDomain()
    IocParser()

# https://habr.com/ru/companies/f_a_c_c_t/news/792672/
# https://habr.com/ru/companies/f_a_c_c_t/articles/726760/
# https://habr.com/ru/companies/f_a_c_c_t/news/747540/