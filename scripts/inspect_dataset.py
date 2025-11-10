import pandas as pd
df = pd.read_csv("data/labeled_urls.csv")
print(df.head(10))
print("\nLabel counts:\n", df['label'].value_counts())
