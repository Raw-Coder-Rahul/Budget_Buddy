import React from 'react';

const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-white rounded-lg p-2 border border-gray-300">
          <p className="text-xs font-semibold text-blue-800 mb-1">
            {payload[0]?.name || "N/A"}
          </p>
          <p className="text-sm text-gray-600">
            Amount:{" "}
            <span className="text-sm font-medium text-gray-900">
              ${payload[0]?.value || 0}
            </span>
          </p>
        </div>
      );
    }
    return null;
};

export default CustomTooltip;
