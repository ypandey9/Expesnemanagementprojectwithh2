package com.demo.ExpenseManagement.dto;

public class CategoryWiseTotal {

	public String categoryName;
	public Double totalAmount;
	
	public CategoryWiseTotal(String categoryName, Double totalAmount) 
	{
		
		this.categoryName = categoryName;
		this.totalAmount = totalAmount;
	}

	public String getCategoryName() {
		return categoryName;
	}

	public void setCategoryName(String categoryName) {
		this.categoryName = categoryName;
	}

	public Double getTotalAmount() {
		return totalAmount;
	}

	public void setTotalAmount(Double totalAmount) {
		this.totalAmount = totalAmount;
	}
	
}
