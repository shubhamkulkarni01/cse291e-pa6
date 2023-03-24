import io
import gzip
import pandas as pd
import pytricia

as_numbers = io.StringIO()
as_org = io.StringIO()

with gzip.open('data/20230101.as-org2info.txt.gz') as f:
    while (line:=f.readline().decode('utf-8')):
        if 'format:' in line:
            as_org.write(line.replace('# format:', ''))
            break

    while (line:=f.readline().decode('utf-8')):
        if 'format:' in line:
            as_numbers.write(line.replace('# format:', ''))
            break
        as_org.write(line)

    while (line:=f.readline().decode('utf-8')):
        as_numbers.write(line)

    as_org.seek(0)
    as_numbers.seek(0)

as_orgs = pd.read_csv(as_org, delimiter='|')
as_numbers = pd.read_csv(as_numbers, delimiter='|')

as_org_data = as_orgs.merge(as_numbers, on='org_id', suffixes=['_org', '_number'])

print('loaded orgs')

pyt = pytricia.PyTricia()

with gzip.open('data/routeviews-rv2-20230201-1200.pfx2as.gz') as f:
    for line in f.readlines():
        ip_addr, netmask, remaining = line.decode('utf-8').split()
        as_number = [ i for i in remaining.split('_') if ',' not in i ]
        pyt[f'{ip_addr}/{netmask}'] = as_number


df = pd.read_csv('data/processed/internet_backscatter.csv')

breakpoint()
