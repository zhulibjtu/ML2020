def factor(n):
    if n<2:
        return 1
    else:
        return n*factor(n-1)
    end
if __name__ == "__main__":
    print(factor(5))