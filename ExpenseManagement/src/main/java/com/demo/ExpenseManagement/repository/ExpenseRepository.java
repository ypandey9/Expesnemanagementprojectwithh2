package com.demo.ExpenseManagement.repository;

import java.time.LocalDate;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.demo.ExpenseManagement.dto.CategoryWiseTotal;
import com.demo.ExpenseManagement.entity.Expense;

@Repository
public interface ExpenseRepository extends JpaRepository<Expense,Long>
{
	@Query("SELECT COALESCE(SUM(e.amount), 0) FROM Expense e")
	public double getTotal();
	//List<Expense> findByUser(User user);
	
	@Query("SELECT new com.demo.ExpenseManagement.dto.CategoryWiseTotal(c.name, SUM(e.amount)) " +
		       "FROM Expense e JOIN e.category c GROUP BY c.name")
		public List<CategoryWiseTotal> getCategoryWiseTotalAmount();
	/*
	This query does the following:

		SELECT new com.demo.ExpenseManagement.dto.CategoryWiseTotal(c.name, SUM(e.amount)): This part of the query selects two fields:

		c.name: The name of the category (c represents a category).
		SUM(e.amount): The total amount of expenses (e.amount) for each category.
		The new keyword creates a new instance of the CategoryWiseTotal DTO (Data Transfer Object) with these two fields.

		FROM Expense e: This specifies that the query is selecting data from the Expense entity (e is an alias for the Expense entity).

		JOIN e.category c: This represents a join operation between the Expense entity (e) and its associated Category entity (c), assuming there is a relationship between these two entities, likely a many-to-one or one-to-many relationship.

		GROUP BY c.name: The query groups the results by the name of the category (c.name). This ensures that the sum of expenses is calculated per category, i.e., for each unique category name.
		*/
	
	@Query("SELECT new com.demo.ExpenseManagement.dto.CategoryWiseTotal(c.name, SUM(e.amount)) " +
		       "FROM Expense e JOIN e.category c " +
		       "WHERE c.name = :categoryName " +
		       "GROUP BY c.name")
		public CategoryWiseTotal getTotalAmountByCategory(@Param("categoryName") String categoryName);

	List<Expense> findBydateBetween(LocalDate startDate, LocalDate endDate);
}
