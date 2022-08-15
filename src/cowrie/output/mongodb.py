from __future__ import annotations
import pymongo
from gridfs import GridFS

from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig

import os

class Output(cowrie.core.output.Output):
    """
    mongodb output
    """

    def start(self):
        db_addr = CowrieConfig.get("output_mongodb", "connection_string")
        db_name = CowrieConfig.get("output_mongodb", "database")

        try:
            self.mongo_client = pymongo.MongoClient(db_addr)
            self.mongo_db = self.mongo_client[db_name]
            self.col_sessiondata = self.mongo_db["sessiondata"]
            self.files = GridFS(self.mongo_db)
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

        elif eventid in ["cowrie.session.file_download", "cowrie.session.file_download.failed", "cowrie.session.file_upload"]: # upload event triggered by sftp/scp
            if (eventid == "cowrie.session.file_download" or eventid == "cowrie.session.file_upload") and entry["shasum"]:
                if not self.files.exists({"filename": entry["shasum"]}):
                    with open("var/lib/cowrie/downloads/" + entry["shasum"], 'rb') as f:
                        self.files.put(f, filename=entry["shasum"])

                self.col_sessiondata.update_one({"session": entry["session"]}, {"$push": {"shasum": entry["shasum"]}}, upsert=True)
            
            if "url" in entry:
                self.col_sessiondata.update_one({"session": entry["session"]}, {"$push": {"url": entry["url"]}})

        elif eventid == "cowrie.log.closed" or eventid == "cowrie.session.closed":
            doc = self.col_sessiondata.find_one({"session": entry["session"]})
            if doc:
                sessiondata["endTime"] = entry["timestamp"]
                self.col_sessiondata.update_one({"session": entry["session"]}, {"$set": {"endTime": sessiondata["endTime"]}})
