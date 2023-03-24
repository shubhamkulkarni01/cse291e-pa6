import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import tqdm

tqdm.tqdm.pandas()

K = 10

# FOR TIMESERIES DF
fmt = '%Y-%m-%d %H:%M:%S %z'
df = pd.read_csv('data/processed/time_series_hour_country.csv')
df.Date = pd.to_datetime(df.Date.str[:-4], format=fmt)
df = (
    df
    .groupby(['NetacqCountry', 'Date'], group_keys=False)['Volume']
    .sum()
    .reset_index()
)

top_K_countries = df.groupby('NetacqCountry')['Volume'].sum().sort_values(ascending=False)[:K].index

df = df[df.NetacqCountry.isin(top_K_countries)][['Date', 'NetacqCountry', 'Volume']]

t = df.groupby('NetacqCountry',group_keys=False)['Volume'].sum()

df['ScaledVolume'] = (
    df
    .groupby('NetacqCountry',group_keys=False)['Volume']
    .apply(lambda x: x / x.sum())
)

sns.lineplot(
    data = df,
    x='Date',
    y='ScaledVolume',
    hue='NetacqCountry',
)

plt.show()
