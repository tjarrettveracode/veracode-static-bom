import sys
import argparse
import logging
import json
import datetime
import csv

import anticrlf
from veracode_api_py import VeracodeAPI as vapi

log = logging.getLogger(__name__)

def setup_logger():
    handler = logging.FileHandler('vcstaticbom.log', encoding='utf8')
    handler.setFormatter(anticrlf.LogFormatter('%(asctime)s - %(levelname)s - %(funcName)s - %(message)s'))
    logger = logging.getLogger(__name__)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

def creds_expire_days_warning():
    creds = vapi().get_creds()
    exp = datetime.datetime.strptime(creds['expiration_ts'], "%Y-%m-%dT%H:%M:%S.%f%z")
    delta = exp - datetime.datetime.now().astimezone() #we get a datetime with timezone...
    if (delta.days < 7):
        print('These API credentials expire ', creds['expiration_ts'])

def get_all_apps():
    applist = vapi().get_apps()
    return applist

def get_app(app_guid):
    return vapi().get_app(app_guid)

def get_findings(app_guid):
    log.info('Getting findings for {}'.format(app_guid))
    return vapi().get_findings(app_guid,scantype='STATIC',annot='FALSE')

def get_modules_list(findings):
    # we use list comprehension to get all the modules and set to build the unique list
    return set([(finding.get('finding_details').get('module')) for finding in findings])

def get_modules_from_summary(app_guid):
    log.info('Getting modules for {}'.format(app_guid))
    summary_report = vapi().get_summary_report(app_guid)
    static_analysis = summary_report.get('static-analysis')
    if static_analysis != None:
        modules = static_analysis.get('modules').get('module')
        return [module['name'] for module in modules]
    else:  
        return []

def get_modules(app_info):
    #define a dict with elements app_guid, app_legacy_id, app_name, scan_url, scan_date, modules

    app_modules_list = {}

    app_modules_list['app_guid'] = app_info.get('guid')
    app_modules_list['app_legacy_id'] = app_info.get('id')
    app_modules_list['app_name'] = app_info.get('profile').get('name')
    log.debug('Checking application guid {} named {} for scan status'.format(app_modules_list['app_guid'], app_modules_list['app_name']))
    scans = app_info["scans"]

    try:
        static_scan = next(scan for scan in scans if scan["scan_type"] == "STATIC")
        if static_scan != None and static_scan["status"] == 'PUBLISHED':
            app_modules_list['scan_url'] = static_scan['scan_url']
            app_modules_list['scan_date'] = static_scan['modified_date']
        else:
            #check policy compliance to see if we have any completed scan
            policy = app_info["profile"]["policies"][0]
            if policy.get('policy_compliance_status') == "NOT_ASSESSED":
                log.info('Application guid {} has no completed static scans.'.format(app_modules_list['app_guid']))
                app_modules_list['modules'] = None
                return app_modules_list
        app_modules_list['modules'] = get_modules_from_summary(app_modules_list['app_guid'])
    except StopIteration:
        log.debug('Application guid {} named {} has no static scans'.format(app_modules_list['app_guid'], app_modules_list['app_name']))

    return app_modules_list

def write_modules_to_csv(modules_list):
    status = 'Writing modules list to vcstaticbom.csv'
    print(status)
    log.info(status)
    fields = [ 'app_guid','app_legacy_id','app_name','scan_url','scan_date','module' ]

    with open("vcstaticbom.csv", "w", newline='') as f:
        w = csv.DictWriter(f, fields)
        w.writeheader()
        for k in modules_list:
            modules = k.get('modules')
            for m in modules:
                w.writerow({'app_guid': k.get('app_guid'), 'app_legacy_id': k.get('app_legacy_id'),
                'app_name': k.get('app_name'), 'scan_url': k.get('scan_url'), 'scan_date': k.get('scan_date'), 'module': m})

def main():
    parser = argparse.ArgumentParser(
        description='This script lists modules in which static findings were identified.')
    parser.add_argument('-a', '--application', required=False, help='Application guid to check for static findings.')
    parser.add_argument('--all', '-l',action='store_true')
    args = parser.parse_args()

    appguid = args.application
    checkall = args.all
    setup_logger()

    # CHECK FOR CREDENTIALS EXPIRATION
    creds_expire_days_warning()

    appcount=0
    app_modules=0
    all_app_modules = []

    if checkall:
        applist = get_all_apps()
        status = "Checking {} applications for a list of modules".format(len(applist))
        log.info(status)
        print(status)
        for app in applist:
            this_app_modules = get_modules(app)
            this_modules = this_app_modules.get('modules')
            if this_modules == None:
                continue
            app_modules_count = len(this_modules)
            if app_modules_count > 0:
                appcount += 1
                app_modules += app_modules_count
                if appcount % 10 == 0:
                    print("Checked {} apps and counting".format(appcount))
            all_app_modules.append(this_app_modules)

    elif appguid != None:
        status = "Checking application {} for a list of modules".format(appguid)
        log.info(status)
        print(status)
        this_app_modules = get_modules(get_app(appguid))
        this_modules = this_app_modules.get('modules')
        if this_modules == None:
            print('No modules for app guid {}'.format(appguid))
            return
        else:
            app_modules_count = len(this_modules)
            if app_modules_count > 0:
                appcount = 1
                app_modules += app_modules_count
            all_app_modules.append(this_app_modules)
    else:
        print('You must either provide an application guid or check all applications.')
        return
    
    write_modules_to_csv(all_app_modules)

    print("Found {} applications with {} modules. See vcstaticbom.csv for details.".format(appcount,app_modules))
    log.info("Found {} applications with {} modules.".format(appcount,app_modules))
    
if __name__ == '__main__':
    main()