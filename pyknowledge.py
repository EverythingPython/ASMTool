import sqlite3
from SQLiteHelper import *

db=Connect('cheatsheet.db')

def exist_table(name):
    cursor.execute


TEXT='TEXT'

def main():
    tbname = 'python'
    if not db.table(tbname).tableExists():
        #create it
        db.table(tbname).withColumns('key','detail').withDataTypes(TEXT,TEXT).createTable()

    results = db.table(tbname).select('key','detail').where('key').like().execute()
    for item in results:
        print(item)

if __name__ == '__main__':
    main()