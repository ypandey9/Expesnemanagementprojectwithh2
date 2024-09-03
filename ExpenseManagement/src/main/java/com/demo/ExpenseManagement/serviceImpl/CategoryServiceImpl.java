package com.demo.ExpenseManagement.serviceImpl;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.demo.ExpenseManagement.entity.Category;
import com.demo.ExpenseManagement.repository.CategoryRepository;
import com.demo.ExpenseManagement.service.CategoryService;

@Service
public class CategoryServiceImpl implements CategoryService {

	@Autowired
	private CategoryRepository categoryRepository;
	
	@Override
	public Category addCategory(Category category) {
		
		return categoryRepository.save(category);
	}

	@Override
	public Category removeCategory(long id) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Category updateCategory(Category Category, long id) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Category getCategoryById(long id) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<Category> getAllCategory() {
		
		return categoryRepository.findAll();
	}

}
