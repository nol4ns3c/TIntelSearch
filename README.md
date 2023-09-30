```
 █████             █████             ████  █████ █████
░░███             ░░███             ░░███ ░░███ ░░███ 
 ░███  ████████   ███████    ██████  ░███  ░░███ ███  
 ░███ ░░███░░███ ░░░███░    ███░░███ ░███   ░░█████   
 ░███  ░███ ░███   ░███    ░███████  ░███    ███░███  
 ░███  ░███ ░███   ░███ ███░███░░░   ░███   ███ ░░███ 
 █████ ████ █████  ░░█████ ░░██████  █████ █████ █████
░░░░░ ░░░░ ░░░░░    ░░░░░   ░░░░░░  ░░░░░ ░░░░░ ░░░░░ 
                                                      
```

Telegram bot for checking maliciousness of ip address and url

## For Installation


``` git clone https://github.com/nol4ns3c/TIntelSearch```

```cd TIntelSearch```

```pip install -r requirements.txt```


## For Usage

Create your telegram bot with BotFather and copy your api key.

```
def main():
    app = ApplicationBuilder().token('[API-KEY]').build()                    # Change API-KEY with your api key
    
```

```
/ipscan [IP]     -   To scan ip address     
/ipscan 8.8.8.8
        
/urlscan [URl]   -   To scan url address    
/urlscan https://google.com
```
