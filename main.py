from core.parsers.dependency_check_parser import Dependencycheckparser
from core.compositionanalysis.dependencycheck import DependencyCheck
from core.parsers.npmaudit_parser import Npmauditparser
from core.parsers.findsecbugs_parser import Fsbparser
from core.parsers.gosec_parser import Gosecparser
from core.vcs.bitbucket import MyRemoteCallbacks
from core.utils.json_parsing import Jsonparsing 
from core.sast.constants import Constants
from core.utils.commands import Command
from core.sast.nodejs import NodeJs
from core.sast.golang import GoLang
from file import check_output_files
from core.utils.utils import Utils
from colorama import Fore, Style
from multiprocessing import Pool
from config.config import Config
from core.sast.java import Java
import multiprocessing
import datetime
import requests
import logging
import shutil
import uuid
import time
import json
import os

mrc = MyRemoteCallbacks()
config = Config()
java = Java()
dc = DependencyCheck()
go = GoLang()
node = NodeJs()
repos = mrc.scan_repos()
command = Command()
jp = Jsonparsing()
const = Constants()
gp = Gosecparser()
fsbp = Fsbparser()
dcp = Dependencycheckparser()
np = Npmauditparser()
utils = Utils()

java_repos = []
go_repos = []
node_repos = []
repos_to_scan = []


def scan_complete():
    """
    """ 
    print(Fore.GREEN +
          "[+]---------- Scan completed -------------" + Style.RESET_ALL)
    logging.info('Completed Scanning')
    return

def scan_all_repos(repos:str):
    """
    Function to intitiate the static analysis for java, node and spotbugs for all repos in the organisation

    accepts list
    """
    pool = Pool(processes=multiprocessing.cpu_count())
    res = pool.map(scan_repo, repos)
    pool.close()
    pool.join()
    return

def scan_repo(repo:str):
    """
    Function to intitiate the static analysis for java, node and spotbugs for a single repo
    """
    
    if repo in node_repos:
        print(
            Fore.YELLOW + "[+]---------- Starting scan for  nodejs project %s -------------" % (repo) + Style.RESET_ALL)
        try:
            command.run_command("npm_audit", repo)
            logging.info('Completed npm_audit for project %s' % (repo))
            np.node_output(repo)
        except:
            logging.debug(
                Fore.RED + "[+]---------- npm_audit Exception -------------" + Style.RESET_ALL)
    
    if repo in go_repos:
        try:
            print(
                Fore.YELLOW + "[+]---------- Starting scan for go project %s -------------" % (repo) + Style.RESET_ALL)
            command.run_command("gosec", repo)
            logging.info('Completed running gosec for project %s' % (repo))
            gp.golang_output(repo)
        except:
            logging.debug('Exception running gosec for project %s' % (repo))

    if repo in java_repos:
        try:
            print(
                Fore.YELLOW + "[+]---------- Starting scan for java project %s -------------" %  (repo) + Style.RESET_ALL)
            
            command.run_command("spotbugs", repo)
            logging.info(Fore.GREEN +'Completed runnning findsecbugs for project %s' % (repo) + Style.RESET_ALL)
            if java.check_build(repo) == "maven":
                fsbp.maven_output(repo)
            elif java.check_build(repo) == "gradle":
                fsbp.gradle_output(repo)
            else:
                pass
        except:
            logging.debug('Exception runnning findsecbugs for project %s' % (repo))
    return

def dependency_check(repo:str):
    """
    Scans all the repos for dependency checking
    """ 
    print(Fore.YELLOW + "[+]---------- DependencyCheck scanning for  %s -------------" % (
        repo) + Style.RESET_ALL)
    try:
        if java.check_build(repo) == "maven":
            dc.dependency_check_maven(repo)
            if not os.path.exists('%s%s/target/dependency-check-report.json' % (config.PATRONUS_DOWNLOAD_LOCATION, repo)):
                dc.dependency_check(repo)
            dcp.dependency_check_results_maven(repo)
        elif java.check_build(repo) == "gradle":
            dc.dependency_check_gradle(repo)
            if not os.path.exists('%s%s/build/reports/dependency-check-report.json' % (config.PATRONUS_DOWNLOAD_LOCATION, repo)):
                dc.dependency_check(repo)
            dcp.dependency_check_results_gradle(repo)
        else:
            dc.dependency_check(repo)
            dcp.node_results(repo)
        logging.info('Completed dependencycheck scanning for project %s' % (repo))
    except:
        logging.debug("Exception while scanning for dependencycheck")
    return

def dependency_check_for_all_repos(repos:str):
    """
    """
    pool = Pool(processes=multiprocessing.cpu_count())
    res = pool.map(dependency_check, repos)
    pool.close()
    pool.join()
    return

def get_all_repos():
    """
    """
    for repo in repos:
        if utils.detect_programming_language(repo[0]) is not None:
            repos_to_scan.append(utils.detect_programming_language(repo[0]))
    return repos_to_scan

def filter_repos_by_lang():
    """
    """
    for repo in repos_to_scan:
        if repo['lang'] == "java":
            java_repos.append(repo['repo'])
        elif repo['lang'] == "go":
            go_repos.append(repo['repo'])
        elif repo['lang'] == "nodejs" or repo['lang'] == "javascript":
            node_repos.append(repo['repo'])
    return

def initiate_scan():
    """
    """
    mrc.clean_all_repos(repos)
    print(Fore.YELLOW +
          "[+]---------- Cloning all repos -------------" + Style.RESET_ALL)
    mrc.clone_all_repository(repos)
    print(Fore.YELLOW +
          "[+]---------- Completed cloning all repos -------------" + Style.RESET_ALL)
    get_all_repos()
    filter_repos_by_lang()
    scan_all_repos(java_repos + go_repos + node_repos)
    dependency_check_for_all_repos(java_repos + node_repos)
    scan_complete()
    return

def sent_to_slack(message:str):
        url = config.PATRONUS_SLACK_WEB_HOOK_URL
        payload = {'text': message}
        requests.post(url, data=json.dumps(payload))
        return

def logo():
    print("""
         ######:
         #######:              ##
         ##   :##              ##
         ##    ##   :####    #######    ##.####   .####.   ##.####   ##    ##   :#####.
         ##   :##   ######   #######    #######  .######.  #######   ##    ##  ########
         #######:   #:  :##    ##       ###.     ###  ###  ###  :##  ##    ##  ##:  .:#
         ######:     :#####    ##       ##       ##.  .##  ##    ##  ##    ##  ##### .
         ##        .#######    ##       ##       ##    ##  ##    ##  ##    ##  .######:
         ##        ## .  ##    ##       ##       ##.  .##  ##    ##  ##    ##     .: ##
         ##        ##:  ###    ##.      ##       ###  ###  ##    ##  ##:  ###  #:.  :##
         ##        ########    #####    ##       .######.  ##    ##   #######  ########
         ##          ###.##    .####    ##        .####.   ##    ##    ###.##  . ####
        """
        )

def main():
    sent_to_slack("Scanning started")
    log_file = os.path.dirname(os.path.abspath(__file__)) +  "/logs/logs.txt"
    logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s', filename=log_file, level=logging.INFO, datefmt='%Y-%m-%d %H:%M:%S')
    logging.info('Starting logging')
    logo()
    initiate_scan()
    sent_to_slack("Scanning completded")
    return

if __name__ == '__main__':
    main()