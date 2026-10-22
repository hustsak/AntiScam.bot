from analyzer.hash import calculate_sha256
from analyzer.file_info import get_file_info
from analyzer.indicators import analyze_filename
from analyzer.risk import calculate_risk

from pathlib import Path
import tempfile


def main():

    with tempfile.TemporaryDirectory() as folder:

        test_file = Path(folder) / "hello.txt"
        test_file.write_text("KhmerShield AI test")

        print("SHA256:")
        print(calculate_sha256(str(test_file)))

        print("\nFILE INFO:")
        print(get_file_info(str(test_file)))

        print("\nSUSPICIOUS FILE TEST:")
        findings = analyze_filename("invoice.pdf.exe")
        print(findings)

        print("\nRISK:")
        print(calculate_risk(findings))


if __name__ == "__main__":
    main()
