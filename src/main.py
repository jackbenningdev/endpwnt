# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
from endpwnt import EndPwnt
from html_reporter import HtmlReporter
def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    e = EndPwnt("C:\\Users\\benni\\endpwnt\\crapi-openapi-spec.yaml", "C:\\Users\\benni\\endpwnt\\config.yaml")
    h = HtmlReporter(e.run_scan())
    h.write("C:\\Users\\benni\\endpwnt\\crapi-openapi-spec.html")
# See PyCharm help at https://www.jetbrains.com/help/pycharm/
