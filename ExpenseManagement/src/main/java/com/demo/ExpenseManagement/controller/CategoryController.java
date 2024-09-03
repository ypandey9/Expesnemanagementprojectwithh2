package com.demo.ExpenseManagement.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.demo.ExpenseManagement.entity.Category;
import com.demo.ExpenseManagement.serviceImpl.CategoryServiceImpl;

@Controller
@RequestMapping("/categories")
public class CategoryController {

	@Autowired
	private CategoryServiceImpl categoryService;
	
	
	@GetMapping("/all")
	public String getAllCategory(Model model) {
		model.addAttribute("categories",categoryService.getAllCategory());
		return "all_category";
	}
	
	@GetMapping("/showform")
	public String showForm(Model model)
	{
		model.addAttribute("newCategory",new Category());
		return "add_category";
	}
	
	@PostMapping("/add")
	public String addCategory(@ModelAttribute Category category) {
		
		categoryService.addCategory(category);
		return "redirect:/categories/all";
	}
	
}
