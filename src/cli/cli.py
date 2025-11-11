def main():
    import argparse
    from scanner.core import Scanner

    parser = argparse.ArgumentParser(description='Web Vulnerability Scanner')
    parser.add_argument('target', type=str, help='Target URL to scan')
    args = parser.parse_args()

    scanner = Scanner()
    scanner.start_scan(args.target)

if __name__ == '__main__':
    main()