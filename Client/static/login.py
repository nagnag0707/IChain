#!/usr/bin/env python
# -*- coding: utf-8 -*-

from browser import document

def login():
    accept_id = document["accept_id"].value
    return accept_id
    
execute_btn = document["login"]
execute_btn.bind("click", login)
