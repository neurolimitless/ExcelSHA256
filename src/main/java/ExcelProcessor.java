import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import java.io.File;
import java.io.FileOutputStream;

public class ExcelProcessor {

    private File input;
    private File output;

    public ExcelProcessor(String inputFileName, String outputFileName) {
        input = new File(inputFileName);
        output = new File(outputFileName);
    }

    public String[] getData(int rows, int columns) {
        String[] rowData = new String[rows * columns];
        int rowIndex = 2;
        int dataIndex = 0; //pointer for rowData array.
        try {
            Workbook workbook = new XSSFWorkbook(input); //creating instance of XLSX object
            Sheet mainSheet = workbook.getSheetAt(0); //get first sheet.
            for (int j = 1; j <= rows; j++) {
                Row currentRow = mainSheet.getRow(rowIndex++); //first row that we read is always third row (in Java counting from 0)
                for (int i = 4; i < 4 + columns; i++) {
                    try {
                        rowData[dataIndex++] = currentRow.getCell(i).getStringCellValue().substring(3);
                    } catch (Exception e) {
                        rowData[dataIndex++] = "";
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return rowData;
    }


    public String getDGI() {
        try {
            Workbook workbook = new XSSFWorkbook(input);
            Sheet sheet = workbook.getSheetAt(0); //main sheet
            Row rowWithDGI = sheet.getRow(1); // second row
            Cell cellWithDGI = rowWithDGI.getCell(2); //third cell
            return cellWithDGI.getStringCellValue();
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public void saveToFile(String[] data) {
        try {
            int rowCount = data.length / 7; //7 columns
            int index = 0;
            Workbook workbook = new XSSFWorkbook();
            Sheet sheet = workbook.createSheet();
            for (int i = 0; i < rowCount; i++) {
                sheet.autoSizeColumn(i);
                Row currentRow = sheet.createRow(i);
                for (int j = 0; j < 7; j++) {
                    Cell currentCell = currentRow.createCell(j);
                    currentCell.setCellValue(data[index++]);
                }
            }
            FileOutputStream fileOutputStream = new FileOutputStream(output);
            workbook.write(fileOutputStream);
            fileOutputStream.flush();
            fileOutputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
