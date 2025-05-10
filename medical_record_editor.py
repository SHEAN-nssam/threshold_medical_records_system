'''
编辑json文件
医生id及患者id要查询变化为对应的姓名
导出为word/pdf格式

附带验签功能
作为单独的路由和编写网页？
'''
import json
from docx import Document
from docx.shared import Inches
from docx.oxml.ns import qn
from docx.shared import Pt
from fpdf import FPDF

def json_to_word(json_file, word_file):
    # 读取 JSON 文件
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # 创建 Word 文档
    doc = Document()

    # 设置文档样式
    style = doc.styles['Normal']
    font = style.font
    font.name = 'Times New Roman'
    font.size = Pt(12)

    # 添加标题
    doc.add_heading('JSON 数据转换', 0)

    # 遍历 JSON 数据并添加到 Word 文档
    for key, value in data.items():
        if isinstance(value, dict):
            doc.add_heading(key, level=1)
            for sub_key, sub_value in value.items():
                doc.add_paragraph(f'{sub_key}: {sub_value}')
        else:
            doc.add_paragraph(f'{key}: {value}')

    # 保存 Word 文档
    doc.save(word_file)
    print(f"Word 文档已保存为: {word_file}")

def json_to_pdf(json_file, pdf_file):
    # 读取 JSON 文件
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # 创建 PDF 文档
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # 添加标题
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="JSON 数据转换", ln=True, align='C')

    # 遍历 JSON 数据并添加到 PDF 文档
    pdf.set_font("Arial", size=12)
    for key, value in data.items():
        if isinstance(value, dict):
            pdf.set_font("Arial", 'B', 14)
            pdf.cell(200, 10, txt=key, ln=True)
            pdf.set_font("Arial", size=12)
            for sub_key, sub_value in value.items():
                pdf.cell(200, 10, txt=f"{sub_key}: {sub_value}", ln=True)
        else:
            pdf.cell(200, 10, txt=f"{key}: {sub_value}", ln=True)

    # 保存 PDF 文档
    pdf.output(pdf_file)
    print(f"PDF 文档已保存为: {pdf_file}")

if __name__ == "__main__":
    # 示例 JSON 文件路径
    json_file = "example.json"

    # 转换为 Word 文档
    word_file = "output.docx"
    json_to_word(json_file, word_file)

    # 转换为 PDF 文档
    pdf_file = "output.pdf"
    json_to_pdf(json_file, pdf_file)