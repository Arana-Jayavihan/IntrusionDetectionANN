import pandas as pd
from sklearn.utils import shuffle

def shuffle_and_divide(file1, file2, output_file_prefix):
    df1 = pd.read_csv(file1)
    df2 = pd.read_csv(file2)

    df_merged = pd.concat([df1, df2], ignore_index=True, sort=False)
    df_shuffled = shuffle(df_merged)

    split_size = len(df_shuffled) // 2

    df1_split = df_shuffled.iloc[:split_size]
    df2_split = df_shuffled.iloc[split_size:]

    output_file1 = f"processedData/trainData{output_file_prefix}.csv"
    output_file2 = f"processedData/testData{output_file_prefix}.csv"
    df1_split.to_csv(output_file1, index=False)
    df2_split.to_csv(output_file2, index=False)

    print(f"Divided and saved shuffled data into '{output_file1}' and '{output_file2}'")

shuffle_and_divide("tmpData/benignData.csv", "tmpData/suspiciousData.csv", "Processed")
