import React from 'react'
import CustomPieChart from '../Charts/CustomPieChart';

const COLORS = ["#18206B", "#FA2C37", "#FF6900"];

const FinanceOverview = ({totalBalance, totalIncome, totalExpense}) => {

    const balanceData = [
        { name: "Total Balance", amount: totalBalance },
        { name: "Total Expenses", amount: totalExpense},
        { name: "Total Income", amount: totalIncome},
    ];
    
  return (
    <div className="className">
        <div className="flex items-center justify-between">
            <h5 className="text-lg">FinanceOverview</h5>
        </div>

        <CustomPieChart
            data={balanceData}
            label="Total Balance"
            totalAmount={`$${totalBalance}`}
            colors={COLORS}
            showTextAnchor
        />
    </div>
  );
};

export default FinanceOverview;