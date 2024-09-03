package com.demo.ExpenseManagement.serviceImpl;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.demo.ExpenseManagement.dto.CategoryWiseTotal;
import com.demo.ExpenseManagement.entity.Expense;
import com.demo.ExpenseManagement.repository.ExpenseRepository;
import com.demo.ExpenseManagement.service.ExpenseService;

@Service
public class ExpenseServiceImpl implements ExpenseService {

	@Autowired
	private ExpenseRepository expenseRepository;
	
	@Override
	public Expense addExpense(Expense expense) {
		return expenseRepository.save(expense);
	}

	@Override
	public void removeExpense(long id) {
		
		expenseRepository.deleteById(id);
	}

	@Override
	public Expense updateExpense(Expense expense, long id) {
		Expense existsExpense=getExpenseById(id);
		existsExpense.setDescription(expense.getDescription());
		existsExpense.setAmount(expense.getAmount());
		existsExpense.setDate(expense.getDate());
		existsExpense.setCategory(expense.getCategory());
		return expenseRepository.save(existsExpense);
	}

	@Override
	public Expense getExpenseById(long id) {
		
		return expenseRepository.findById(id).get();
				
	}

	@Override
	public List<Expense> getAllExpense() {
		// TODO Auto-generated method stub
		return expenseRepository.findAll();
	}

	@Override
	public double getTotalExpense() {
		// TODO Auto-generated method stub
		if((String.valueOf(expenseRepository.getTotal())==null))
				return 0.0;
		else
			return expenseRepository.getTotal();
	}

	@Override
	public List<CategoryWiseTotal> getCategoryWiseTotalAmount() {
		// TODO Auto-generated method stub
		return expenseRepository.getCategoryWiseTotalAmount();
	}

	@Override
	public CategoryWiseTotal getTotalAmountByCategory(String categoryName) {
		// TODO Auto-generated method stub
		return expenseRepository.getTotalAmountByCategory(categoryName);
	}

	@Override
	public List<Expense> findByexpenseCreatedOnBetween(LocalDate startDate, LocalDate endDate) {
		// TODO Auto-generated method stub
		return expenseRepository.findBydateBetween(startDate, endDate);
	}

}
