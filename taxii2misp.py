from taxii2client.v21 import Server
from taxii2client.v21 import Collection, as_pages
from stix2 import TAXIICollectionSource, Filter, parse
from pymisp import PyMISP
from pymisp import MISPEvent
import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from datetime import datetime
import uuid
from datetime import date, datetime, timedelta

today = date.today()

# We are all adults and know of the danger of self-signed SSL certs - no need to read it all the time
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# The URL pointing to your MISP instance
misp_url= ""
# Your MISP API key
misp_api = ""
# Your TAXII user
taxii_user = ''
# Your TAXII password
taxii_password = ''
# Insert alle collections in here which you want to ingest
collections=['a08485ea-f622-46d7-927a-def48f393419','ce1b8c35-69d0-41c0-9e47-5edc6c88584a'  ]
    
misp_src = PyMISP(misp_url, misp_api, False, 'json')

server = Server('https://health-isac.cyware.com/ctixapi/ctix21/taxii/', user=taxii_user, password=taxii_password)

# We loop over every collection
for c in collections:
    
    collection = Collection('https://health-isac.cyware.com/ctixapi/ctix21/collections/' + c, user=taxii_user, password=taxii_password)
    print("Now checking collection " + collection.title)

    # We need to store or received STIX output to a file since PyMISP does not have a function
    # to load data from a string but only from a file
    with open('envelope.json', 'w') as f:
        yesterday = datetime.today() - timedelta(days = 1 )
        # Get all objects which were added after our last poll
        items = collection.get_objects(added_after=str(yesterday).replace(" ", "T") + "Z")
        print("Found " + str(len(items['objects'])) + " new items!")
                
        if len(items['objects']) > 0: 
            # Generating random bundle uuid since this is missing from H-ISAC data and leads to a 500 error when submitting to MISP
            uu = "bundle--" + str(uuid.uuid1())
                    
            j = {}
            j['type'] = 'bundle'
            j['id'] = uu
            j['objects'] = []
            
            # Our "original" objects (IOCs) we received from H-ISAC are added to a new array 
            for s in items['objects']:
                j['objects'].append(s)            
            
            # Afterwards we write everything to disk so we can ingest it via MISP
            # HINT: If some uploads later fail with a 500 you might want to have a look at the content of envelope.json
            # DIRECTLY after writing it to disk since it might be empty (Antivirus detection?)
            f.write(json.dumps(j))
            
            # Now we are uploading our stuff
            response = misp_src.upload_stix('envelope.json',version='2')
            
            response_j = response.json()
            if response.status_code == 200:
                # We are loading our MISP event again since we need to make some adjustments especially for the attributes
                # The STIX objects do have labels which help with attributing the malicious indicators. Since PyMISP does
                # not automatically add them as tag, we do so manually
                event = misp_src.get_event(response_j['Event']['id'], pythonify=True) 
                if len(event.Attribute) == 0:
                    # If a MISP event has 0 attributes, that means that only STIX metadata
                    # was added because it's a duplicate event so we can safely delete it again
                    print("Event " + str(event.id) + " has only STIX metadata added - deleting it since it's a duplicate")
                    misp_src.delete_event(event.id)
                else:   
                    event.info = "H-ISAC Daily Digest for time between " + yesterday.strftime("%B %d, %Y") + " and " + today.strftime("%B %d, %Y") + " - " +collection.title
                    
                    for s in items['objects']:
                        try:
                            # We extract the IOC from the string
                            ioc = s['name'][s['name'].index(": ")+2:]
                            
                            # We then loop over all the attributes in our event
                            for t in event.Attribute:                            
                                # We disable the correlation flag
                                t.disable_correlation = True
                                # ... and if the IOC matches our attribute value
                                if t.value == ioc:
                                    # ... we add the corresponding tags aka labels
                                    for p in s['labels']:
                                        resp = t.add_tag(p)
                                        print(resp)
                        except Exception as e:
                            # print("Fail: " + str(e))
                            continue
                            
                    misp_src.update_event(event, response_j['Event']['id'])     
                    print("Status code from MISP: " + str(response.status_code))
                    
                    # We also need to change the distribution of the event to our sharing group
                    misp_src.change_sharing_group_on_entity(event, 1)
                    
                    # Possible bug in PyMISP at uploading STIX: Every marking definition at the end of the STIX file is used as a tag for the event
                    # which leads us to events who have tlp:white, tlp:amber, etc. at the same time. We therefor remove all those tags and readd
                    # them according to the collection
                    for tag in event.Tag:
                        print("Removing tag " + tag.name)
                        resp = misp_src.untag(event.uuid, tag.name)
                        
                    # Then we need to readd the appropriate tag
                    if "WHITE" in collection.title:
                        print("Adding tag 'tlp:white' to event")
                        resp = misp_src.tag(event.uuid,'tlp:white')
                    elif "GREEN" in collection.title:
                        print("Adding tag 'tlp:green' to event")
                        resp = misp_src.tag(event.uuid,'tlp:green')
                    elif "AMBER" in collection.title:
                        print("Adding tag 'tlp:amber' to event")
                        resp = misp_src.tag(event.uuid,'tlp:amber')
                    elif "CISCP" in collection.title:
                        print("Adding tag 'tlp:amber' to event")
                        resp = misp_src.tag(event.uuid,'tlp:amber')
                    elif "AIS" in collection.title:
                        print("Adding tag 'tlp:green' to event")
                        resp = misp_src.tag(event.uuid,'tlp:green')
                        
                    # Finally, we publish the event without sending a mail
                    misp_src.publish(event.id, alert=False)                    
            else:
                print("MISP returned a non success status code " + str(response.status_code) + " - " + response.text)
    
    