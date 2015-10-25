# -*- coding: utf-8 -*-
"""Project metadata

Information describing the project.
"""

# The package name, which is also the "UNIX name" for the project.
package = 'stringphone'
project = "String phone"
project_no_spaces = project.replace(' ', '')
version = '0.1'
description = ('String phone is a secure communications with a focus on ease of'
               ' use, simplicity and small size, suitable for embedded devices.'
               ' It provides both encryption and authentication of messages.')
authors = ['Stavros Korokithakis']
authors_string = ', '.join(authors)
emails = ['hi@stavros.io']
license = 'BSD'
copyright = '2015 ' + authors_string
url = 'https://github.com/skorokithakis/stringphone'
