def generate_500kb_file():
    # 生成500kB的文本（500,000字节）
    size = 500 * 1000  # 500kB
    
    # 方法1: 生成重复模式的文本（高效）
    base_text = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\n"
    repetitions = size // len(base_text) + 1
    
    content = base_text * repetitions
    content = content[:size]  # 精确截取到500KB
    
    # 写入文件
    with open("500kb_text.txt", "w", encoding="utf-8") as f:
        f.write(content)
    
    print(f"生成文件大小: {len(content)} 字节 ({len(content)/1024:.2f} KB)")
    return content

# 执行生成
text_data = generate_500kb_file()
