from __future__ import annotations
import pymongo
from gridfs import GridFS

from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig

import os
import re
import hashlib

class Output(cowrie.core.output.Output):
    """
    mongodb output
    """

    def start(self):
        db_addr = CowrieConfig.get("output_mongodb", "connection_string")
        db_name = CowrieConfig.get("output_mongodb", "database")

        try:
            self.mongo_client = pymongo.MongoClient(db_addr, connect=False)
            self.mongo_db = self.mongo_client[db_name]
            self.col_sessiondata = self.mongo_db["sessiondata"]
            self.files = GridFS(self.mongo_db)

            self.header_regex = re.compile(b'^C0[0-7]{3} [0-9]+ .*') # matching SCP metadata header - file permissions + file size + file name
            self.not_found_regex = re.compile(b'^.+: No such file or directory')
        except Exception as e:
            log.msg(f"output_mongodb: Error: {str(e)}")

    def stop(self):
        self.mongo_client.close()

    def write(self, entry):
        for i in list(entry.keys()):
            # Remove twisted 15 legacy keys
            if i.startswith("log_"):
                del entry[i]

        eventid = entry["eventid"]
        sessiondata = {}

        if eventid == "cowrie.login.success":
            sessiondata["sensor"] = entry["sensor"]
            sessiondata["startTime"] = entry["timestamp"]
            sessiondata["endTime"] = ""
            sessiondata["credentials"] = {"username": entry["username"], "password": entry["password"]}
            sessiondata["src_ip"] = entry["src_ip"]
            sessiondata["session"] = entry["session"]
            sessiondata["commands"] = []
            sessiondata["shasum"] = []
            sessiondata["url"] = []
            log.msg(sessiondata)
            self.col_sessiondata.insert_one(sessiondata)

        elif eventid == "cowrie.command.input":
            self.col_sessiondata.update_one({"session": entry["session"]}, {"$push": {"commands": entry["input"]}})

        elif eventid in ["cowrie.session.file_download", "cowrie.session.file_download.failed", "cowrie.session.file_upload"]: # upload event to expand coverage of files
            if (eventid == "cowrie.session.file_download" or eventid == "cowrie.session.file_upload") and entry["shasum"]: 
        
                with open("var/lib/cowrie/downloads/" + entry["shasum"], 'rb') as f:
                    
                    data = f.read()
                    shasum = entry["shasum"]

                    header_match = self.header_regex.match(data) # matches format of SCP metadata
                
                if header_match:
                    with open("var/lib/cowrie/downloads/" + entry["shasum"], 'r+b') as f:
                        f.write(data[header_match.end()+1:-1]) # -1 removes extra null byte provided by SCP

                        entry["filename"] = data[:header_match.end()+1].split()[2].decode()

                        f.truncate() # these two lines remove SCP metadata

                        shasum = hashlib.sha256(data[header_match.end()+1:-1]).hexdigest()

                    os.rename("var/lib/cowrie/downloads/" + entry["shasum"], "var/lib/cowrie/downloads/" + str(shasum))

                    if not self.files.exists({"filename": shasum}):
                        self.files.put(open("var/lib/cowrie/downloads/" + shasum, 'rb'), filename=shasum)

                    self.col_sessiondata.update_one({"session": entry["session"]}, {"$push": {"shasum": shasum}}, upsert=True)

                elif (self.not_found_regex.match(data)):
                    
                    log.msg(
                        format="%(shahash)s is believed to be SCP not found error so removing",
                        shahash=entry["shasum"]
                    )

                    os.remove("var/lib/cowrie/downloads/" + entry["shasum"])

                else: # for all non-SCP files
                    if not self.files.exists({"filename": shasum}):
                        self.files.put(open("var/lib/cowrie/downloads/" + shasum, 'rb'), filename=shasum)

                    self.col_sessiondata.update_one({"session": entry["session"]}, {"$push": {"shasum": shasum}}, upsert=True)

            if "url" in entry:
                self.col_sessiondata.update_one({"session": entry["session"]}, {"$push": {"url": entry["url"]}})

            if "filename" in entry and eventid == "cowrie.session.file_upload": # file_upload events get tagged with name. check necessary as download events filename field is path cowrie stores in as opposed to original name
                self.col_sessiondata.update_one({"session": entry["session"]}, {"$push": {"filenames."+shasum: entry["filename"]}})
            
            if eventid == "cowrie.session.file_download" and "destfile" in entry and "shasum" in entry and entry["destfile"] and entry["shasum"]:
                filename = entry["destfile"].split('/')[-1] # getting just filename, ignoring path
                self.col_sessiondata.update_one({"session": entry["session"]}, {"$push": {"filenames."+shasum: filename}})


        elif eventid == "cowrie.log.closed" or eventid == "cowrie.session.closed":
            doc = self.col_sessiondata.find_one({"session": entry["session"]})
            if doc:
                sessiondata["endTime"] = entry["timestamp"]
                self.col_sessiondata.update_one({"session": entry["session"]}, {"$set": {"endTime": sessiondata["endTime"]}})

                if doc["shasum"] and not doc["commands"]:
                    self.col_sessiondata.update_one({"session": entry["session"]}, {"$set": {"fileAnalysed": False}}) # For uploads without commands to force analysis of files
