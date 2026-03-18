import os
import json
import asyncio

WRITE_TO_FILE = os.getenv('WRITE_TO_FILE', 'False')
PARSER = os.getenv('PARSER', 'tls-scanner')
NATS_ENABLED = os.getenv('NATS_ENABLED', 'False')
NATS_URL     = os.getenv('NATS_URL', 'nats://localhost:4222')
NATS_SUBJECT = os.getenv('NATS_SUBJECT', 'samma-io.scan')



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

async def _nats_publish(payload: bytes):
    import nats
    nc = await nats.connect(NATS_URL)
    await nc.publish(NATS_SUBJECT, payload)
    await nc.drain()

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
    _tags_raw = os.getenv('SAMMA_IO_TAGS', 'scanner')
    json_samma['tags'] = [t.strip() for t in _tags_raw.split(',') if t.strip()]
    json_samma['json'] = os.getenv('SAMMA_IO_JSON', '{}')



    #Adding the extra data
    json_data['samma-io'] = json_samma

    #If WRITE_TO_FILE != False
    if WRITE_TO_FILE != "False":
        WriteToFile(json_data)

    if NATS_ENABLED != "False":
        payload = json.dumps(json_data, ensure_ascii=False,
                             sort_keys=True, separators=(',', ': ')).encode()
        asyncio.run(_nats_publish(payload))

    print(json_data)
