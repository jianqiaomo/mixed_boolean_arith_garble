import pandas as pd
import openpyxl


def analyze_comm_text_file(file_path):
    '''
    Analyze the communication results from the text file to a list.
    Each element in the list is a dictionary containing the communication data of a trunk.

    :param file_path:
    :return: results list(dict)
    '''
    results = []

    with open(file_path, 'r') as file:
        trunks = file.read().strip().split('\n\n')  # Split by empty lines to get trunks

        for trunk_i, trunk in enumerate(trunks):

            lines = trunk.strip().split('\n')
            if len(lines) < 19:
                continue  # Skip incomplete trunks
            # if trunk_i > 0:
            #     # drop the first line of the trunk
            #     lines = lines[1:]

            trunk_data = {}

            # Gb Output 5 op 3: 8; Bundle CRT [2, 3, 5]; Bitwidth 4; Operate Add;
            setting_line = lines[0].split(';')
            if len(setting_line) >= 4:
                # key, value = setting_line[1].strip().split(' ', 1)
                # trunk_data[key] = value.split('[')[1][:-1] if "CRT" in setting_line[1] else value.split('[')[0]
                for part in setting_line[1:4]:
                    key, value = part.strip().split(' ', 1)
                    trunk_data[key] = value

            #   garbler inputs:                    8 // communication: 1.024 Kb
            gbin_line = lines[2].split()
            if len(gbin_line) >= 2:
                key = ' '.join(gbin_line[:2])
                value = float(gbin_line[-2])
                trunk_data[key] = value

            #   evaluator inputs:                  8 // communication: 3.072 Kb
            evin_line = lines[3].split()
            if len(evin_line) >= 2:
                key = ' '.join(evin_line[:2])
                value = float(evin_line[-2])
                trunk_data[key] = value

            #   output ciphertexts:                0 // communication: 0.000 Kb
            output_line = lines[5].split()
            if len(output_line) >= 2:
                key = ' '.join(output_line[:2])
                value = float(output_line[-2])
                trunk_data[key] = value

            #   constants:                         0 // communication: 0.000 Kb
            constant_line = lines[6].split()
            if len(constant_line) >= 1:
                key = constant_line[0]
                value = float(constant_line[-2])
                trunk_data[key] = value

            #   ciphertexts:                       0 // communication: 0.000 Mb (0.000 Kb)
            ciphertext_line = lines[17].replace('(', ' ').split()
            if len(ciphertext_line) >= 1:
                key = ciphertext_line[0]
                value = float(ciphertext_line[-2])
                trunk_data[key] = value

            results.append(trunk_data)

    return results


def analyze_time_text_file(file_path):
    """
    Analyze the time results from the text file to a list.

    :param file_path:
    :return: results list(dict)
    """
    results = []
    with open(file_path, 'r') as file:
        lines = file.read().strip().split('\n')  # Split by lines

        for line_i, line in enumerate(lines):
            line_data = {}

            # line format: Gb Output 5 op 3: 8; Bundle CRT[2, 3, 5]; Bitwidth 4; Operate Add; Time: 7 us;
            line = line.split('; ')
            if len(line) >= 5:
                for part in line[1:4]:
                    key, value = part.strip().split(' ', 1)
                    line_data[key] = value
                line_data[line[4].replace(';', '').split(': ')[0]] = line[4].replace(';', '').split(': ')[1].split()[0]

            results.append(line_data)

    return results


def tablize_comm_results(results):
    """
    Put the communication results list(dict) to a table.
    
    :param results: list(dict)
    :return: dataframe
    """
    # Create a dictionary to store the data for the table
    table_titles = ['garbler inputs:', 'evaluator inputs:', 'output ciphertexts:', 'constants:', 'ciphertexts:']
    results_df = pd.DataFrame()

    for table_title in table_titles:
        table_data = {" ": {}, table_title: {}}
        for result in results:
            # Construct the column name from 'Bundle' and 'Bitwidth'
            column_name = f"{result['Bitwidth']}_{result['Bundle']}"

            # Row name from 'Operate'
            row_name = result['Operate']

            # Value from 'garbler inputs:'
            value = result[table_title]

            # Initialize the row if it doesn't exist
            if row_name not in table_data:
                table_data[row_name] = {}

            # Set the value in the appropriate cell
            table_data[row_name][column_name] = value
            table_data[table_title][column_name] = result['Bundle']

        # Convert the table data to a DataFrame, Transpose to have rows as index
        results_df = pd.concat([results_df, pd.DataFrame(table_data).T])
    return results_df


def tablize_time_results(results):
    """
    Put the timing results list(dict) to a table.

    :param results: list(dict)
    :return: dataframe
    """
    # Create a dictionary to store the data for the table
    table_titles = {'Garbling time': [], 'Evaluating time': []}
    results_df = pd.DataFrame()

    # Seperate results to two lists, one for which has 'Garbling time' in its keys, the other for 'Evaluating time'
    for table_title in table_titles.keys():
        table_titles[table_title] = [result for result in results if table_title in result.keys()]

    for table_title, table_results in table_titles.items():
        table_data = {" ": {}, table_title: {}}
        for result in table_results:
            # Construct the column name from 'Bundle' and 'Bitwidth'
            column_name = f"{result['Bitwidth']}_{result['Bundle']}"

            # Row name from 'Operate'
            row_name = result['Operate']

            # Value from 'garbler inputs:'
            value = result[table_title]

            # Initialize the row if it doesn't exist
            if row_name not in table_data:
                table_data[row_name] = {}

            # Set the value in the appropriate cell
            table_data[row_name][column_name] = value
            table_data[table_title][column_name] = result['Bundle']

        # Convert the table data to a DataFrame, Transpose to have rows as index
        results_df = pd.concat([results_df, pd.DataFrame(table_data).T])
    return results_df


def save_to_excel(df, output_path):
    with pd.ExcelWriter(output_path) as writer:
        df.to_excel(writer, index=True)
    print(f"Data has been successfully written to {output_path}")


if __name__ == "__main__":
    """
    run method_profile.rs to evaluate the communication or run time results of each workload
    """

    analyzing = 'time'  # 'comm' (communication) or 'time' (run time)
    file_path = f'{analyzing}_result.txt'  # print text result from method_profile.rs 
    output_path = f'{analyzing}_result.xlsx'  # Path to your output Excel file

    if analyzing == 'comm':
        analyzed_data = analyze_comm_text_file(file_path)
        results_df = tablize_comm_results(analyzed_data)
    elif analyzing == 'time':
        analyzed_data = analyze_time_text_file(file_path)
        results_df = tablize_time_results(analyzed_data)
    else:
        raise ValueError("Please specify the type of data you want to analyze: 'comm' or 'time'")

    save_to_excel(results_df, output_path)
    print(f"End...")
