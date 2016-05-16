public class Main {
    public static void main(String[] args) {
        if (args == null || args[0] == null || args[1] == null)
            System.out.println("Please enter valid arguments. jar sha256.jar input.xlsx output.xlsx");
        else {
            ExcelProcessor excelProcessor = new ExcelProcessor(args[0], args[1]);
            String DGI = excelProcessor.getDGI();
            if (DGI.equals("07 01")) {
                System.out.println("DGI 07 01");
                String[] data = excelProcessor.getData(3, 3); //3 rows, 3 columns
                excelProcessor.saveToFile(DataProcessor.DGI0701(data));
            } else if (DGI.equals("07 02")) {
                System.out.println("DGI 07 02");
                String[] data = excelProcessor.getData(4, 3); //4 rows, 3 columns
                excelProcessor.saveToFile(DataProcessor.DGI0702(data));
            }
            System.out.println("Successfully saved.");
        }
    }
}
