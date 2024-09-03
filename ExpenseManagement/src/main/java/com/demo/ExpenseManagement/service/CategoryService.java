package com.demo.ExpenseManagement.service;

import java.util.List;

import com.demo.ExpenseManagement.entity.Category;

public interface CategoryService {

	public Category addCategory(Category category);
	public Category removeCategory(long id);
	public Category updateCategory(Category category ,long id);
	public Category getCategoryById(long id);
	public List<Category> getAllCategory();
}
