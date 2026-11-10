"""Build the Chinese experiment report DOCX from report.md."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from docx import Document
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Inches, Pt, RGBColor


def set_run_font(run, name: str, size: float, *, bold: bool = False, color: str = "000000") -> None:
    run.font.name = name
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.color.rgb = RGBColor.from_string(color)
    props = run._element.get_or_add_rPr()
    fonts = props.rFonts
    if fonts is None:
        fonts = OxmlElement("w:rFonts")
        props.insert(0, fonts)
    fonts.set(qn("w:ascii"), name)
    fonts.set(qn("w:hAnsi"), name)
    fonts.set(qn("w:eastAsia"), "Microsoft YaHei")


def set_shading(element, fill: str) -> None:
    props = element.get_or_add_pPr() if element.tag.endswith("}p") else element.get_or_add_tcPr()
    shading = props.find(qn("w:shd"))
    if shading is None:
        shading = OxmlElement("w:shd")
        props.append(shading)
    shading.set(qn("w:fill"), fill)
    shading.set(qn("w:val"), "clear")


def set_cell_margins(cell, top: int = 90, start: int = 110, bottom: int = 90, end: int = 110) -> None:
    tc = cell._tc
    tc_pr = tc.get_or_add_tcPr()
    margins = tc_pr.first_child_found_in("w:tcMar")
    if margins is None:
        margins = OxmlElement("w:tcMar")
        tc_pr.append(margins)
    for edge, value in (("top", top), ("start", start), ("bottom", bottom), ("end", end)):
        node = margins.find(qn(f"w:{edge}"))
        if node is None:
            node = OxmlElement(f"w:{edge}")
            margins.append(node)
        node.set(qn("w:w"), str(value))
        node.set(qn("w:type"), "dxa")


def set_table_borders(table) -> None:
    tbl_pr = table._tbl.tblPr
    borders = tbl_pr.first_child_found_in("w:tblBorders")
    if borders is None:
        borders = OxmlElement("w:tblBorders")
        tbl_pr.append(borders)
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        tag = f"w:{edge}"
        node = borders.find(qn(tag))
        if node is None:
            node = OxmlElement(tag)
            borders.append(node)
        node.set(qn("w:val"), "single")
        node.set(qn("w:sz"), "4")
        node.set(qn("w:space"), "0")
        node.set(qn("w:color"), "D9E0E5")


def is_table_separator(line: str) -> bool:
    cells = [part.strip() for part in line.strip().strip("|").split("|")]
    return bool(cells) and all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells)


def add_table(document: Document, rows: list[list[str]]) -> None:
    if not rows:
        return
    table = document.add_table(rows=1, cols=len(rows[0]))
    table.autofit = False
    table.alignment = 1
    set_table_borders(table)
    column_count = len(rows[0])
    available = Inches(6.9)
    if column_count == 4:
        fractions = (0.17, 0.32, 0.22, 0.29)
    elif column_count == 3:
        fractions = (0.18, 0.40, 0.42)
    else:
        fractions = tuple(1 / column_count for _ in range(column_count))
    widths = [int(available * fraction) for fraction in fractions]
    for row_index, values in enumerate(rows):
        cells = table.rows[0].cells if row_index == 0 else table.add_row().cells
        row_properties = table.rows[row_index]._tr.get_or_add_trPr()
        row_properties.append(OxmlElement("w:cantSplit"))
        for col_index, value in enumerate(values):
            cell = cells[col_index]
            cell.width = widths[col_index]
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            set_cell_margins(cell)
            set_shading(cell._tc, "1E4E66" if row_index == 0 else ("F2F6F8" if row_index % 2 else "FFFFFF"))
            paragraph = cell.paragraphs[0]
            paragraph.paragraph_format.space_after = Pt(0)
            paragraph.paragraph_format.line_spacing = 1.08
            run = paragraph.add_run(value.strip())
            set_run_font(run, "Microsoft YaHei", 8.8, bold=(row_index == 0), color=("FFFFFF" if row_index == 0 else "202830"))


def add_code_block(document: Document, lines: list[str]) -> None:
    paragraph = document.add_paragraph()
    paragraph.paragraph_format.left_indent = Cm(0.18)
    paragraph.paragraph_format.right_indent = Cm(0.18)
    paragraph.paragraph_format.space_before = Pt(3)
    paragraph.paragraph_format.space_after = Pt(8)
    paragraph.paragraph_format.line_spacing = 1.0
    paragraph.paragraph_format.keep_together = True
    set_shading(paragraph._p, "F1F4F6")
    for index, line in enumerate(lines):
        if index:
            paragraph.add_run().add_break()
        run = paragraph.add_run(line.rstrip())
        set_run_font(run, "Consolas", 8.2, color="243746")


def add_page_field(paragraph) -> None:
    run = paragraph.add_run()
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    instruction = OxmlElement("w:instrText")
    instruction.set(qn("xml:space"), "preserve")
    instruction.text = " PAGE "
    separate = OxmlElement("w:fldChar")
    separate.set(qn("w:fldCharType"), "separate")
    text = OxmlElement("w:t")
    text.text = "1"
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    run._r.extend((begin, instruction, separate, text, end))
    set_run_font(run, "Microsoft YaHei", 8.5, color="5B6770")


def build(source: Path, output: Path) -> None:
    lines = source.read_text(encoding="utf-8").splitlines()
    document = Document()
    section = document.sections[0]
    section.page_width = Cm(21)
    section.page_height = Cm(29.7)
    section.top_margin = Cm(1.85)
    section.bottom_margin = Cm(1.8)
    section.left_margin = Cm(1.9)
    section.right_margin = Cm(1.9)

    normal = document.styles["Normal"]
    normal.font.name = "Microsoft YaHei"
    normal.font.size = Pt(10.2)
    normal.font.color.rgb = RGBColor(32, 40, 48)
    normal._element.rPr.rFonts.set(qn("w:eastAsia"), "Microsoft YaHei")
    normal.paragraph_format.space_after = Pt(5)
    normal.paragraph_format.line_spacing = 1.14
    for style_name, size in (("Heading 1", 15), ("Heading 2", 11.8)):
        style = document.styles[style_name]
        style.font.name = "Microsoft YaHei"
        style.font.size = Pt(size)
        style.font.bold = True
        style.font.color.rgb = RGBColor(0, 0, 0)
        style._element.rPr.rFonts.set(qn("w:eastAsia"), "Microsoft YaHei")
        style.paragraph_format.space_before = Pt(12 if style_name == "Heading 1" else 8)
        style.paragraph_format.space_after = Pt(5)
        style.paragraph_format.keep_with_next = True
        style_properties = style._element.pPr
        if style_properties is not None:
            for tag in ("w:numPr", "w:pBdr"):
                item = style_properties.find(qn(tag))
                if item is not None:
                    style_properties.remove(item)

    title_properties = document.styles["Title"]._element.pPr
    if title_properties is not None:
        for tag in ("w:pBdr", "w:numPr"):
            item = title_properties.find(qn(tag))
            if item is not None:
                title_properties.remove(item)

    header = section.header.paragraphs[0]
    header.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    header_run = header.add_run("软件与系统安全  ·  实验 1B")
    set_run_font(header_run, "Microsoft YaHei", 8.5, color="52616B")
    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    footer_run = footer.add_run("安全文件传输软件设计与实现  ·  ")
    set_run_font(footer_run, "Microsoft YaHei", 8.5, color="5B6770")
    add_page_field(footer)

    index = 0
    first_heading = True
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if not stripped:
            index += 1
            continue
        if stripped.startswith("```"):
            index += 1
            block = []
            while index < len(lines) and not lines[index].strip().startswith("```"):
                block.append(lines[index])
                index += 1
            add_code_block(document, block)
            index += 1
            continue
        if stripped.startswith("|") and index + 1 < len(lines) and is_table_separator(lines[index + 1]):
            header_cells = [part.strip() for part in stripped.strip("|").split("|")]
            rows = [header_cells]
            index += 2
            while index < len(lines) and lines[index].strip().startswith("|"):
                cells = [part.strip() for part in lines[index].strip().strip("|").split("|")]
                if len(cells) == len(header_cells):
                    rows.append(cells)
                index += 1
            add_table(document, rows)
            continue
        heading = re.match(r"^(#{1,3})\s+(.*)$", stripped)
        if heading:
            level = len(heading.group(1))
            title = heading.group(2)
            if level == 1 and first_heading:
                paragraph = document.add_paragraph(style="Title")
                paragraph.paragraph_format.space_after = Pt(3)
                paragraph_properties = paragraph._p.get_or_add_pPr()
                for tag in ("w:pBdr", "w:numPr"):
                    item = paragraph_properties.find(qn(tag))
                    if item is not None:
                        paragraph_properties.remove(item)
                run = paragraph.add_run(title)
                set_run_font(run, "Microsoft YaHei", 21, bold=True)
                first_heading = False
            else:
                paragraph = document.add_paragraph(style="Normal")
                paragraph.paragraph_format.space_before = Pt(12 if level == 2 else 8)
                paragraph.paragraph_format.space_after = Pt(5)
                paragraph.paragraph_format.keep_with_next = True
                run = paragraph.add_run(title)
                set_run_font(run, "Microsoft YaHei", 15 if level == 2 else 11.8, bold=True)
            index += 1
            continue
        if stripped.startswith("- "):
            paragraph = document.add_paragraph(style="List Bullet")
            paragraph.add_run(stripped[2:])
        elif re.match(r"^\d+\.\s+", stripped):
            paragraph = document.add_paragraph(style="List Number")
            paragraph.add_run(re.sub(r"^\d+\.\s+", "", stripped))
        else:
            paragraph = document.add_paragraph()
            paragraph.paragraph_format.widow_control = True
            paragraph.add_run(stripped.replace("`", ""))
        for run in paragraph.runs:
            set_run_font(run, "Microsoft YaHei", 10.2)
        index += 1

    document.core_properties.title = "安全文件传输软件设计与实现"
    document.core_properties.subject = "《软件与系统安全》实验 1B"
    document.core_properties.author = ""
    output.parent.mkdir(parents=True, exist_ok=True)
    document.save(output)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1] / "report.md")
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "report.docx")
    args = parser.parse_args()
    build(args.source, args.output)
    print(f"Created {args.output.resolve()}")


if __name__ == "__main__":
    main()
