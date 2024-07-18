import pandas as pd
import openpyxl

def analyze_comm_text_file(file_path):
    results = []

    with open(file_path, 'r') as file:
        trunks = file.read().strip().split('\n\n')  # Split by empty lines to get trunks

        for trunk_i, trunk in enumerate(trunks):

            lines = trunk.strip().split('\n')
            if len(lines) < 19:
                continue  # Skip incomplete trunks
            if trunk_i > 0:
                # drop the first line of the trunk
                lines = lines[1:]

            trunk_data = {}

            # Gb experiment settings. Bundle Binary. Bitwidth 8. Operate XOR.
            second_line = lines[1].split('.')
            if len(second_line) >= 4:
                for part in second_line[1:4]:
                    key, value = part.strip().split(' ', 1)
                    trunk_data[key] = value

            #   garbler inputs:                    8 // communication: 1.024 Kb
            fourth_line = lines[3].split()
            if len(fourth_line) >= 2:
                key = ' '.join(fourth_line[:2])
                value = float(fourth_line[-2])
                trunk_data[key] = value

            #   evaluator inputs:                  8 // communication: 3.072 Kb
            fifth_line = lines[4].split()
            if len(fifth_line) >= 2:
                key = ' '.join(fifth_line[:2])
                value = float(fifth_line[-2])
                trunk_data[key] = value

            #   output ciphertexts:                0 // communication: 0.000 Kb
            seventh_line = lines[6].split()
            if len(seventh_line) >= 2:
                key = ' '.join(seventh_line[:2])
                value = float(seventh_line[-2])
                trunk_data[key] = value

            #   constants:                         0 // communication: 0.000 Kb
            eighth_line = lines[7].split()
            if len(eighth_line) >= 1:
                key = eighth_line[0]
                value = float(eighth_line[-2])
                trunk_data[key] = value

            #   ciphertexts:                       0 // communication: 0.000 Mb (0.000 Kb)
            nineteenth_line = lines[18].replace('(', ' ').split()
            if len(nineteenth_line) >= 1:
                key = nineteenth_line[0]
                value = float(nineteenth_line[-2])
                trunk_data[key] = value

            results.append(trunk_data)

    return results


def analyze_comm_results_as_table(results):
    # Create a dictionary to store the data for the table
    table_titles = ['garbler inputs:', 'evaluator inputs:', 'output ciphertexts:', 'constants:', 'ciphertexts:']
    results_df = pd.DataFrame()

    for table_title in table_titles:
        table_data = {" ": {}, table_title: {}}
        for result in results:
            # Construct the column name from 'Bundle' and 'Bitwidth'
            column_name = f"{result['Bundle']}_{result['Bitwidth']}"

            # Row name from 'Operate'
            row_name = result['Operate']

            # Value from 'garbler inputs:'
            value = result[table_title]

            # Initialize the row if it doesn't exist
            if row_name not in table_data:
                table_data[row_name] = {}

            # Set the value in the appropriate cell
            table_data[row_name][column_name] = value

        # Convert the table data to a DataFrame, Transpose to have rows as index
        results_df = pd.concat([results_df, pd.DataFrame(table_data).T])
    return results_df


def save_to_excel(df, output_path):
    with pd.ExcelWriter(output_path) as writer:
        df.to_excel(writer, index=True)
    print(f"Data has been successfully written to {output_path}")


if __name__ == "__main__":
    file_path = 'commresult.txt'  # Path to your input text file
    output_path = 'commresult.xlsx'  # Path to your output Excel file

    analyzed_data = analyze_comm_text_file(file_path)
    results_df = analyze_comm_results_as_table(analyzed_data)
    save_to_excel(results_df, output_path)
    print(f"End...")
