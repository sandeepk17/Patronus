class Config:
    SSH_PUB_KEY = "SSH_KEYS/id_rsa.pub"
    SSH_PRI_KEY = "SSH_KEYS/id_rsa"
    SSH_PASSWORD = ""

    BITBUCKET_USERNAME = ""
    BITBUCKET_APP_PASSWORD = ""
    BITBUCKET_OWNER = ""

    DB_HOST = ""
    DB_DATABASE = ""
    DB_USER = ""
    DB_PASSWORD =""

    #Patronus configurations
    PATRONUS_SCAN_TYPE = ""  
    PATRONUS_SLACK_ALERT= "" 
    PATRONUS_SLACK_WEB_HOOK_URL = ""
    PATRONUS_ES_PUSH = "" 
    PATRONUS_ES_URL = ""
    PATRONUS_DOWNLOAD_LOCATION = "/tmp/"
    PATRONUS_SUPPORTED_LANG = ["java", "go", "nodejs", "javascript"] 