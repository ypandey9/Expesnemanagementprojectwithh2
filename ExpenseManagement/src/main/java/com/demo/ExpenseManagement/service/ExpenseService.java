package com.demo.ExpenseManagement.service;

import java.time.LocalDate;
import java.util.List;

import com.demo.ExpenseManagement.dto.CategoryWiseTotal;
import com.demo.ExpenseManagement.entity.Expense;

public interface ExpenseService {

	public Expense addExpense(Expense expense);
	public void removeExpense(long id);
	public Expense updateExpense(Expense expense ,long id);
	public Expense getExpenseById(long id);
	public List<Expense> getAllExpense();
	public double getTotalExpense();
	public List<CategoryWiseTotal> getCategoryWiseTotalAmount();
	public CategoryWiseTotal getTotalAmountByCategory(String categoryName);
	List<Expense> findByexpenseCreatedOnBetween(LocalDate startDate, LocalDate endDate);
}
