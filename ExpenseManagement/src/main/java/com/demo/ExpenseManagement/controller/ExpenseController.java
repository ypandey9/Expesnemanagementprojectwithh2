package com.demo.ExpenseManagement.controller;

import java.io.IOException;
import java.time.LocalDate;
import java.util.List;

import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.demo.ExpenseManagement.dto.CategoryWiseTotal;
import com.demo.ExpenseManagement.entity.Category;
import com.demo.ExpenseManagement.entity.Expense;
import com.demo.ExpenseManagement.serviceImpl.CategoryServiceImpl;
import com.demo.ExpenseManagement.serviceImpl.ExpenseServiceImpl;
import com.itextpdf.io.source.ByteArrayOutputStream;

@Controller
@RequestMapping("/expenses")
public class ExpenseController {

	@Autowired
	private ExpenseServiceImpl expenseService;
	
	@Autowired
	private CategoryServiceImpl catService;
	
	@GetMapping("/test")
	public String test() {
	return "This is a test Mapping";	
	}
	
	@GetMapping("/all")
	public String findAll(Model model) {
		model.addAttribute("expenses",expenseService.getAllExpense());
		model.addAttribute("total",expenseService.getTotalExpense());
		return "expenses";
	}
	
	@GetMapping("/{id}")
	public Expense getExpenseById(@PathVariable long id) {
		return expenseService.getExpenseById(id);
	}
	
	@GetMapping("/showaddform")
	public String showAddForm(Model model) {
		List<Category> categories=catService.getAllCategory();
		model.addAttribute("categories",categories);
		 model.addAttribute("newExpense",new Expense());
		return "addExpense";
	}
	
	@PostMapping("/add")
	public String addExpense(@ModelAttribute Expense expense) {
		
		expenseService.addExpense(expense);
		return "redirect:/expenses/all";
		
	}
	
	@PostMapping("/delete/{id}")
	public String deleteExpense(@PathVariable long id)
	{
		expenseService.removeExpense(id);
		return "redirect:/expenses/all";
	}
	
	@GetMapping("/update/form/{id}")
	public String updateForm(Model model,@PathVariable long id) {
		Expense expense=expenseService.getExpenseById(id);
		model.addAttribute("expense",expense);
		return "update_expense";
	}
	
	@PostMapping("/update/{id}")
	public String updateExpense(@ModelAttribute Expense expense,@PathVariable long id) {
		expenseService.updateExpense(expense, id);
		return "redirect:/expenses/all";
	}
	
	 @GetMapping("/categorieswise-data")
	    public String getCategoryWiseData(Model model) {
	        List<CategoryWiseTotal> categoryWiseData = expenseService.getCategoryWiseTotalAmount();
	        double grandTotal = categoryWiseData.stream().mapToDouble(CategoryWiseTotal::getTotalAmount).sum();
	        model.addAttribute("categoryWiseData", categoryWiseData);
	        model.addAttribute("grandTotal", grandTotal);
	        return "categorieswise_data";
	 }
	 
	 @GetMapping("/category-total")
		public String showCategoryTotalForm(Model model,@RequestParam(value="categoryName",required=false) String categoryName)
		{
			List<Category> categories=catService.getAllCategory();
			model.addAttribute("categories", categories);
			
			if(categoryName!=null) {
				CategoryWiseTotal categoryWiseTotal=expenseService.getTotalAmountByCategory(categoryName);
				model.addAttribute("categoryWiseTotal", categoryWiseTotal);
			}
			
			return "category-total";
		}
	 
	 @GetMapping("/show-filter-form")
	 public String showFilterForm()
	 {
		 return "filter_expense";
	 }
	 
	 @GetMapping("/filter")
	 public String getExpensesBetweenDates(@RequestParam ("startDate") @DateTimeFormat(iso=DateTimeFormat.ISO.DATE) LocalDate startDate,
			 @RequestParam("endDate") @DateTimeFormat(iso=DateTimeFormat.ISO.DATE) LocalDate endDate,Model model) {
		 List<Expense> expenses=expenseService.findByexpenseCreatedOnBetween(startDate, endDate);
		 model.addAttribute("expenses", expenses);
		 model.addAttribute("startDate", startDate);
		 model.addAttribute("endDate", endDate);
		 return "show_filter_expense";
	 }
	 
	   @GetMapping("/export-excel")
	    public ResponseEntity<byte[]> exportExpensesToExcel(@RequestParam("startDate") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate startDate,
	     @RequestParam("endDate") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate endDate) throws IOException {
	    
	    	List<Expense> expenses=expenseService.findByexpenseCreatedOnBetween(startDate, endDate);
	    	
	    	Workbook workbook=new XSSFWorkbook();
	    	Sheet sheet=workbook.createSheet("expenses");
	    	Row headerRow=sheet.createRow(0);
	    	headerRow.createCell(0).setCellValue("ID");
	    	headerRow.createCell(1).setCellValue("Description");
	    	headerRow.createCell(2).setCellValue("Amount");
	    	headerRow.createCell(3).setCellValue("Date");
	    	headerRow.createCell(4).setCellValue("Category");
	    	
	    	int rowNum=1;
	    	
	    	for (Expense expense:expenses)
	    	{
	    		Row row=sheet.createRow(rowNum++);
	    		row.createCell(0).setCellValue(expense.getId());
	    		row.createCell(1).setCellValue(expense.getDescription());
	    		row.createCell(2).setCellValue(expense.getAmount());
	    		row.createCell(3).setCellValue(expense.getDate());
	    		row.createCell(4).setCellValue(expense.getCategory().getName());
	    	}
	    		ByteArrayOutputStream out= new ByteArrayOutputStream();
	    		workbook.write(out);
	    		workbook.close();
	    		
	    		byte[] excelData=out.toByteArray();
	    		HttpHeaders headers=new HttpHeaders();
	    		headers.set(HttpHeaders.CONTENT_DISPOSITION,"attachment;filename=expenses.xlsx");
	    		headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
	    		return ResponseEntity.ok()
	    				.headers(headers)
	    				.body(excelData);
	    		
	    	}
	    	
	    }

