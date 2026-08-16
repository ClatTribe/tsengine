import lxml.etree as ET
from flask import request
def h(): return ET.fromstring(request.data, ET.XMLParser(resolve_entities=True))
