import os
import json

WRITE_TO_FILE = os.getenv('WRITE_TO_FILE', 'False')
PARSER = os.getenv('PARSER', 'tls-scanner')



#if we want to write to file lets set it up
if WRITE_TO_FILE != "False":
    f = open("/out/{}.json".format(PARSER), "a")




def WriteToFile(json_data):
    '''
    Write content into file
    '''
    json.dump(json_data, f, ensure_ascii=False,  sort_keys=True, separators=(',', ': '))
    f.write("\n")

def endThis():
    '''
    When the scans is done we want to end all if this in a nice way.

    - first we send a log to put logger so we get a mark in the files that we are done
    - then we write to the file /out/die -- this till other service to also shu down
    '''

    #Log end message
    endJson={"scan":"done"}
    logger(endJson)
    f = open("/out/die", "w")
    f.write("time to die")
    f.close()

def logger(json_data):
    '''
    This is where we parse our json and

    - Add json data from the deployment
    - Send data to samma.io
    - Print out the data in json format
    '''
    # Samma tags
    json_samma={}
    json_samma['scanner'] = os.getenv('SAMMA_IO_SCANNER', 'tls-scanner')
    json_samma['id'] = os.getenv('SAMMA_IO_ID', '1234')
    json_samma['tags'] = os.getenv('SAMMA_IO_TAGS', "['scanner']")
    json_samma['json'] = os.getenv('SAMMA_IO_JSON', '{}')



    #Adding the extra data
    json_data['samma-io'] = json_samma

    #If WRITE_TO_FILE != False
    if WRITE_TO_FILE != "False":
        WriteToFile(json_data)

    print(json_data)
