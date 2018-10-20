import mysql.connector
from mysql.connector import errorcode

DB_NAME = 'portal_api'

operation = "INSERT INTO portal_api.events (id, func_id, input, output, error, status) VALUES (NULL, '2', 'test_from_python2', 'out test1', '0', '1')"
#operation = 'select * from events'
config = {
        'raise_on_warnings': True,
        'failover' : [{
                'user': 'root',
                'password': 'k@ngar0o1!',
                'host': '172.18.0.30',
                'port': 3306,
                'database': 'portal_api',
                }, 
		{
                'user': 'root',
                'password': 'k@ngar0o1!',
                'host': '172.18.0.34',
                'port': 3306,
                'database': 'portal_api',
		},
		{
                'user': 'root',
                'password': 'k@ngar0o1!',
                'host': '172.18.0.26',
                'port': 3306,
                'database': 'portal_api',
                }]
}
conn = mysql.connector.connect(**config)

cursor = conn.cursor()

try:
  for result in cursor.execute(operation, multi=True):
     if result.with_rows:
        print("rows producted by statement '{}':".format(result.statement))
        row = cursor.fetchone()
        while row:
           print(row)
           row = cursor.fetchone()
     else:
        print("Number of rows affeted by statement '{}':{}".format(result.statement, result.rowcount))
except mysql.connector.Error as err:
        print(err.msg)
#conn.close()
conn.commit()
