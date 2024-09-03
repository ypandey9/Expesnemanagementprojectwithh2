package com.demo.ExpenseManagement.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.demo.ExpenseManagement.entity.Category;

@Repository
public interface CategoryRepository extends JpaRepository<Category,Long> {

//	@Query("SELECT c.Category FROM Category c")
//	public String getCategories();
}
