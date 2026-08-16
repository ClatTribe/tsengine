import pickle
from flask import request
def h(): return pickle.loads(request.data)
