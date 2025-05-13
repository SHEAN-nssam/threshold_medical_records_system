import json
import os
from docx import Document
from docx.shared import Inches, Pt
from docx.oxml.ns import qn
from fpdf import FPDF

def json_to_word(json_data, word_file):
    # 创建 Word 文档
    doc = Document()

    # 设置文档样式
    style = doc.styles['Normal']
    font = style.font
    font.name = '宋体'  # 修改为常见中文字体
    font.size = Pt(12)

    # 添加标题
    doc.add_heading('医疗记录', 0)

    # 遍历 JSON 数据并添加到 Word 文档
    for record in json_data:
        # 添加记录标题
        doc.add_heading(f'记录ID: {record["medical_record_id"]}', level=1)

        # 添加患者信息
        doc.add_heading('基本信息', level=2)
        doc.add_paragraph(f'患者ID: {record["patient_id"]}')
        doc.add_paragraph(f'医生ID: {record["doctor_id"]}')
        doc.add_paragraph(f'就诊日期: {record["visit_date"]}')
        doc.add_paragraph(f'科室: {record["department"]}')

        # 添加医疗记录详细信息
        doc.add_heading('医疗记录详细信息', level=2)
        doc.add_paragraph(f'患者主诉: {record["patient_complaint"]}')
        doc.add_paragraph(f'病史: {record["medical_history"]}')
        doc.add_paragraph(f'体格检查: {record["physical_examination"]}')
        doc.add_paragraph(f'辅助检查: {record["auxiliary_examination"]}')
        doc.add_paragraph(f'诊断: {record["diagnosis"]}')
        doc.add_paragraph(f'治疗建议: {record["treatment_advice"]}')

        # 添加签名信息
        doc.add_heading('签名信息', level=2)
        doc.add_paragraph(f'医生签名: {record["doctor_signature"]}')
        doc.add_paragraph(f'创建时间: {record["created_at"]}')
        doc.add_paragraph(f'医生公钥: {record["doctor_public_key"]}')
        doc.add_paragraph(f'验证字符串: {record["to_cal"]}')
        doc.add_paragraph(f'验证签名: {record["to_verify_signature"]}')

        # 添加分页符
        doc.add_page_break()

        # 设置汉字字体
    for paragraph in doc.paragraphs:
        for run in paragraph.runs:
            run.font.name = '宋体'
            run._element.rPr.rFonts.set(qn('w:eastAsia'), '宋体')

    # 保存 Word 文档
    doc.save(word_file)
    print(f"Word 文档已保存为: {word_file}")

def json_to_pdf(json_data, pdf_file):
    # 创建 PDF 文档
    pdf = FPDF()
    pdf.add_page()
    current_dir = os.path.dirname(__file__)  # 获取当前脚本所在目录
    font_path = os.path.join(current_dir, "simsun.ttf")  # 指定字体文件路径

    pdf.add_font("SimSun", style="", fname=font_path, uni=True)  # 添加宋体常规字体
    pdf.set_font("SimSun", size=10)

    # 添加标题
    pdf.set_font("SimSun", '', 14)
    pdf.cell(200, 10, txt="医疗记录", ln=True, align='C')

    # 遍历 JSON 数据并添加到 PDF 文档
    for record in json_data:
        # 添加记录标题
        pdf.set_font("SimSun", '', 10)
        pdf.cell(200, 10, txt=f'病历ID: {record["medical_record_id"]}', ln=True)

        # 添加患者信息
        pdf.set_font("SimSun", '', 12)
        pdf.cell(200, 10, txt='基本信息', ln=True)
        pdf.set_font("SimSun", size=10)
        pdf.cell(200, 10, txt=f'患者ID: {record["patient_id"]}', ln=True)
        pdf.cell(200, 10, txt=f'医生ID: {record["doctor_id"]}', ln=True)
        pdf.cell(200, 10, txt=f'就诊日期: {record["visit_date"]}', ln=True)
        pdf.cell(200, 10, txt=f'科室: {record["department"]}', ln=True)

        # 添加医疗记录详细信息
        pdf.set_font("SimSun", '', 12)
        pdf.cell(200, 10, txt='医疗记录详细信息', ln=True)
        pdf.set_font("SimSun", size=10)
        pdf.multi_cell(180, 10, txt=f'患者主诉: {record["patient_complaint"]}', align='L')
        pdf.multi_cell(180, 10, txt=f'病史: {record["medical_history"]}', align='L')
        pdf.multi_cell(180, 10, txt=f'体格检查: {record["physical_examination"]}', align='L')
        pdf.multi_cell(180, 10, txt=f'辅助检查: {record["auxiliary_examination"]}', align='L')
        pdf.multi_cell(180, 10, txt=f'诊断: {record["diagnosis"]}', align='L')
        pdf.multi_cell(180, 10, txt=f'治疗建议: {record["treatment_advice"]}', align='L')

        # 添加签名信息
        pdf.set_font("SimSun", '', 12)
        pdf.cell(200, 10, txt='签名信息', ln=True)
        pdf.set_font("SimSun", size=10)
        # 使用 multi_cell 方法处理长字符串自动换行
        pdf.multi_cell(180, 10, txt=f'医生签名: {record["doctor_signature"]}', align='L')
        pdf.multi_cell(180, 10, txt=f'创建时间: {record["created_at"]}', align='L')
        pdf.multi_cell(180, 10, txt=f'医生公钥: {record["doctor_public_key"]}', align='L')
        pdf.multi_cell(180, 10, txt=f'验证字符串: {record["to_cal"]}', align='L')
        pdf.multi_cell(180, 10, txt=f'验证用哈希: {record["to_verify_signature"]}', align='L')

        # 添加分页符
        pdf.add_page()

    # 保存 PDF 文档
    pdf.output(pdf_file)
    print(f"PDF 文档已保存为: {pdf_file}")

if __name__ == "__main__":
    # 示例 JSON 文件路径
    json_file = r"F:\2025-1spring\250314\medical_records_proposal_3_20250509_091337.json"

    # 检查 JSON 文件是否存在
    if not os.path.exists(json_file):
        print(f"JSON 文件 '{json_file}' 不存在。")
        exit(1)

    # 读取 JSON 文件
    with open(json_file, 'r', encoding='utf-8') as f:
        json_data = json.load(f)

    # 转换为 Word 文档
    word_file = "medical_records.docx"
    json_to_word(json_data, word_file)

    # 转换为 PDF 文档
    pdf_file = "medical_records.pdf"
    json_to_pdf(json_data, pdf_file)
